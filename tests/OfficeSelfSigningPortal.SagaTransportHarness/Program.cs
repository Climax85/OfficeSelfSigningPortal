using System.Collections.Concurrent;
using MassTransit;
using Npgsql;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using OfficeSelfSigningPortal.SigningService.Data;
using OfficeSelfSigningPortal.SigningService.Messaging;
using OfficeSelfSigningPortal.WorkerService.Data;
using OfficeSelfSigningPortal.WorkerService.Messaging;
using OfficeSelfSigningPortal.WorkerService.Saga;
using Ossp.Audit;
using Ossp.Contracts;

// Transport-Harness des Seams S2 (AK-40, TC-39, TM-19/AK-39/TC-30).
// Läuft als eigener Prozess (kein Testrunner): die Integrationstests orchestrieren
// Container und rufen diesen Harness mit den Connection Strings auf; der Exitcode
// und die MARKER-Zeilen auf stdout sind das Prüfergebnis.
//
// Aufruf: harness <postgres-connstr> <rabbitmq-connstr> <worker|signing> <portal-connstr> [signing-connstr]

var pg = args[0];
var rabbit = args[1];
var modus = args[2];
var portalPg = args[3];
var signingPg = args.Length > 4 ? args[4] : pg;

var retry = new OsspRetryOptions { Limit = 3, MinDelay = TimeSpan.FromMilliseconds(50), MaxDelay = TimeSpan.FromMilliseconds(200) };
var jobFailed = new ConcurrentBag<JobFailed>();

async Task MigrateAsync<TContext>(string connectionString) where TContext : DbContext
{
    var services = new ServiceCollection();
    services.AddDbContext<TContext>(options => options.UseNpgsql(connectionString));
    await using var provider = services.BuildServiceProvider();
    await using var scope = provider.CreateAsyncScope();
    await scope.ServiceProvider.GetRequiredService<TContext>().Database.MigrateAsync();
}

async Task<IHost> StartWorkerHostAsync(string rolle)
{
    var builder = Host.CreateApplicationBuilder();
    builder.Logging.ClearProviders();
    builder.Logging.AddConsole();
    builder.Logging.SetMinimumLevel(LogLevel.Warning);
    builder.Services.AddDbContext<WorkerDbContext>(options => options.UseNpgsql(pg));
    // Konsolidierter Audit-Trail (Ticket 06): Übergänge schreiben append-only in
    // die portal-DB (SHA-256-Hash-Kette); der WorkerService ist nur ein Writer.
    builder.Services.AddAuditTrail(portalPg);
    builder.Services.AddSingleton<ISagaAuditWriter, SagaAuditTrailWriter>();
    builder.Services.AddMassTransit(x =>
    {
        x.AddAnalysisSaga(useEntityFrameworkRepository: true);
        x.AddEntityFrameworkOutbox<WorkerDbContext>(o =>
        {
            o.UsePostgres();
            o.QueryDelay = TimeSpan.FromSeconds(1);
        });
        x.UsingRabbitMq((context, cfg) =>
        {
            cfg.Host(rabbit);
            cfg.ReceiveEndpoint(QueueNames.AnalysisSaga, e =>
                AnalysisSagaBusConfiguration.ConfigureSagaEndpoint(e, context, retry, useEntityFrameworkOutbox: true));
            cfg.ReceiveEndpoint(QueueNames.ScanRequestedError, e =>
                AnalysisSagaBusConfiguration.ConfigureScanDeadLetterEndpoint(e, context));
        });
    });
    var host = builder.Build();
    await host.StartAsync();
    Console.WriteLine($"MARKER HOST-START {rolle}");
    return host;
}

async Task<IHost> StartSigningHostAsync()
{
    var builder = Host.CreateApplicationBuilder();
    builder.Logging.ClearProviders();
    builder.Logging.AddConsole();
    builder.Logging.SetMinimumLevel(LogLevel.Warning);
    // Guard-Ablehnungen (AK-39) auditiert der Guard in denselben Trail (Ticket 06).
    builder.Services.AddAuditTrail(portalPg);
    builder.Services.AddSingleton<ISagaStateReader>(_ => new PostgresSagaStateReader(pg));
    builder.Services.AddMassTransit(x =>
    {
        x.AddSigningGuard();
        x.UsingRabbitMq((context, cfg) =>
        {
            cfg.Host(rabbit);
            cfg.ReceiveEndpoint(QueueNames.SignMacroRequested, e =>
                SigningGuardBusConfiguration.ConfigureSigningGuardEndpoint(
                    e, context, retry.Limit, retry.MinDelay, retry.MaxDelay));
        });
    });
    var host = builder.Build();
    await host.StartAsync();
    Console.WriteLine("MARKER HOST-START signing");
    return host;
}

async Task<IHost> StartPublisherAsync()
{
    var builder = Host.CreateApplicationBuilder();
    builder.Logging.ClearProviders();
    builder.Logging.AddConsole();
    builder.Logging.SetMinimumLevel(LogLevel.Warning);
    builder.Services.AddSingleton(jobFailed);
    builder.Services.AddMassTransit(x =>
    {
        x.UsingRabbitMq((context, cfg) =>
        {
            cfg.Host(rabbit);
            cfg.ReceiveEndpoint("ossp.slice-publisher", e =>
                e.Handler<JobFailed>(ctx =>
                {
                    jobFailed.Add(ctx.Message);
                    return Task.CompletedTask;
                }));
        });
    });
    var host = builder.Build();
    await host.StartAsync();
    Console.WriteLine("MARKER HOST-START publisher");
    return host;
}

async Task<string?> QuerySagaStateAsync(Guid id)
{
    await using var connection = new NpgsqlConnection(pg);
    await connection.OpenAsync();
    await using var command = new NpgsqlCommand(
        "SELECT \"CurrentState\" FROM \"analysis_saga\" WHERE \"CorrelationId\" = @id", connection);
    command.Parameters.AddWithValue("id", id);
    return await command.ExecuteScalarAsync() as string;
}

async Task PublishUntilSagaStateAsync(IBus bus, Func<ScanRequested> messageFactory, Guid id, string expected, int timeoutSeconds = 120)
{
    // Broker-Topologie-Race robust machen: Der erste Publish kann vor der
    // Queue-Bindung des Consumers verloren gehen (unroutable). Erst
    // veröffentlichen, der in der Persistenz ankommt, zählt — jeder Publish
    // überquert denselben echten Broker.
    var deadline = DateTime.UtcNow + TimeSpan.FromSeconds(timeoutSeconds);
    while (DateTime.UtcNow < deadline)
    {
        await bus.Publish(messageFactory());
        var state = await QuerySagaStateAsync(id);
        if (state == expected)
        {
            Console.WriteLine($"MARKER STATE {expected}");
            return;
        }

        await Task.Delay(2000);
    }

    Console.WriteLine(await DumpPostgresDiagnosticsAsync());
    throw new InvalidOperationException($"Saga {id} nicht in Zustand {expected}.");
}

async Task<string> WaitForSagaStateAsync(Guid id, string expected, int timeoutSeconds = 90)
{
    var deadline = DateTime.UtcNow + TimeSpan.FromSeconds(timeoutSeconds);
    while (DateTime.UtcNow < deadline)
    {
        var state = await QuerySagaStateAsync(id);
        if (state == expected)
        {
            Console.WriteLine($"MARKER STATE {expected}");
            return state;
        }

        await Task.Delay(150);
    }

    var zuletzt = await QuerySagaStateAsync(id);
    Console.WriteLine(await DumpPostgresDiagnosticsAsync());
    throw new InvalidOperationException($"Saga {id} nicht in Zustand {expected} (letzter: {zuletzt ?? "<keine Zeile>"}).");
}

async Task<string> DumpPostgresDiagnosticsAsync()
{
    await using var connection = new NpgsqlConnection(pg);
    await connection.OpenAsync();
    await using var command = new NpgsqlCommand(
        """
        SELECT a.pid, a.state, a.wait_event_type, a.wait_event, left(a.query, 120) AS query
        FROM pg_stat_activity a
        WHERE a.datname = current_database() AND a.pid <> pg_backend_pid()
        ORDER BY a.pid;
        SELECT l.pid, l.relation::regclass AS relation, l.mode, l.granted
        FROM pg_locks l
        WHERE l.pid <> pg_backend_pid() AND l.relation IS NOT NULL
        ORDER BY l.pid, l.relation;
        """, connection);

    var sb = new System.Text.StringBuilder();
    await using (var reader = await command.ExecuteReaderAsync())
    {
        do
        {
            while (await reader.ReadAsync())
            {
                sb.AppendLine(string.Join(" | ", Enumerable.Range(0, reader.FieldCount).Select(i => $"{reader.GetName(i)}={reader.GetValue(i)}")));
            }
        }
        while (await reader.NextResultAsync());
    }

    return $"POSTGRES-DIAGNOSTIK:{Environment.NewLine}{sb}";
}

async Task<int> CountAuditTrailEntriesAsync(Guid id, string category)
{
    await using var connection = new NpgsqlConnection(portalPg);
    await connection.OpenAsync();
    await using var command = new NpgsqlCommand(
        "SELECT COUNT(*) FROM audit_trail WHERE \"JobId\" = @id AND \"Category\" = @category", connection);
    command.Parameters.AddWithValue("id", id);
    command.Parameters.AddWithValue("category", category);
    return Convert.ToInt32(await command.ExecuteScalarAsync());
}

static ScanRequested CreateScanRequested(Guid id) => new(
    id, Guid.NewGuid(), Convert.ToHexString(System.Security.Cryptography.SHA256.HashData("blob"u8)),
    "doku.xlsm", "xlsm", 1024, "submitter-1", "submitter-1@example.org", DateTimeOffset.UtcNow);

static ScanCompleted CreateScanCompleted(Guid id, Verdict verdict) => new(
    id, verdict, Score: verdict == Verdict.Clean ? 5 : 45, "scoring-v0.1;ruleset-2025-09",
    Findings: [], Engines: [new EngineResult("heuristics", EngineState.Ok, null)],
    MacroPresent: true, ModuleCount: 2, CompletedAt: DateTimeOffset.UtcNow);

static SignMacroRequested CreateSignMacroRequested(Guid id) => new(
    id, Guid.NewGuid(), Convert.ToHexString(System.Security.Cryptography.SHA256.HashData("blob"u8)),
    "doku.xlsm", "xlsm", "system:auto-sign", DateTimeOffset.UtcNow);

try
{
    if (modus == "worker")
    {
        await MigrateAsync<WorkerDbContext>(pg);
        await MigrateAsync<AuditDbContext>(portalPg);
        var jobId = Guid.NewGuid();
        using var workerA = await StartWorkerHostAsync("worker-A");
        using var publisher = await StartPublisherAsync();
        var bus = publisher.Services.GetRequiredService<IBus>();

        await PublishUntilSagaStateAsync(bus, () => CreateScanRequested(jobId), jobId, SagaStateNames.ScanLaeuft);

        // Worker-Neustart mitten im Vorgang (TC-39): kein Auftragsverlust
        await workerA.StopAsync();
        workerA.Dispose();
        using var workerB = await StartWorkerHostAsync("worker-B");

        await bus.Publish(CreateScanCompleted(jobId, Verdict.Clean));
        await WaitForSagaStateAsync(jobId, SagaStateNames.SignierungAngefragt);

        await bus.Publish(new SignMacroCompleted(jobId, Guid.NewGuid(), DateTimeOffset.UtcNow));
        await WaitForSagaStateAsync(jobId, SagaStateNames.Signiert);

        var auditCount = await CountAuditTrailEntriesAsync(jobId, AuditCategories.Saga);
        Console.WriteLine($"MARKER AUDIT-COUNT {auditCount}");
        if (auditCount < 4)
        {
            throw new InvalidOperationException($"Nur {auditCount} Audit-Einträge — Übergänge wurden nicht protokolliert.");
        }
    }
    else
    {
        await MigrateAsync<WorkerDbContext>(pg);
        await MigrateAsync<SigningDbContext>(signingPg);
        await MigrateAsync<AuditDbContext>(portalPg);
        var jobId = Guid.NewGuid();
        using var worker = await StartWorkerHostAsync("worker");
        using var publisher = await StartPublisherAsync();
        var bus = publisher.Services.GetRequiredService<IBus>();

        await PublishUntilSagaStateAsync(bus, () => CreateScanRequested(jobId), jobId, SagaStateNames.ScanLaeuft);

        using var signing = await StartSigningHostAsync();
        await Task.Delay(500);

        // Fremd-Publish auf die Sign-Queue, Vorgang ist aber in ScanLaeuft (TM-19)
        await bus.Publish(CreateSignMacroRequested(jobId));
        var deadline = DateTime.UtcNow + TimeSpan.FromSeconds(30);
        while (!jobFailed.Any(m => m.JobId == jobId) && DateTime.UtcNow < deadline)
        {
            await Task.Delay(100);
        }

        var abgelehnt = jobFailed.FirstOrDefault(m => m.JobId == jobId)
            ?? throw new InvalidOperationException("Kein JobFailed eingetroffen — Guard hat nicht abgelehnt.");
        if (abgelehnt.Stage != "signing" || abgelehnt.Retryable)
        {
            throw new InvalidOperationException($"Unerwarteter JobFailed: Stage={abgelehnt.Stage}, Retryable={abgelehnt.Retryable}");
        }

        Console.WriteLine("MARKER GUARD-REJECTED");
        if (await QuerySagaStateAsync(jobId) != SagaStateNames.ScanLaeuft)
        {
            throw new InvalidOperationException("Vorgang hat den Status nach Guard-Ablehnung geändert.");
        }

        var incidents = await CountAuditTrailEntriesAsync(jobId, AuditCategories.Guard);
        Console.WriteLine($"MARKER INCIDENTS {incidents}");
        if (incidents != 1)
        {
            throw new InvalidOperationException($"Erwartet 1 Vorfall, gefunden {incidents}.");
        }

        // Regulärer Pfad: Clean-Scan → SignierungAngefragt → Guard akzeptiert
        await bus.Publish(CreateScanCompleted(jobId, Verdict.Clean));
        await WaitForSagaStateAsync(jobId, SagaStateNames.SignierungAngefragt);
        await bus.Publish(CreateSignMacroRequested(jobId));
        await Task.Delay(2000);
        if (jobFailed.Count(m => m.JobId == jobId) != 1)
        {
            throw new InvalidOperationException("Guard hat den legitimen Request fälschlich abgelehnt.");
        }

        Console.WriteLine("MARKER GUARD-ACCEPTED");
    }

    Console.WriteLine("MARKER SUCCESS");
    return 0;
}
catch (Exception ex)
{
    Console.WriteLine($"MARKER FAILURE {ex.GetType().Name}: {ex.Message}");
    return 1;
}
