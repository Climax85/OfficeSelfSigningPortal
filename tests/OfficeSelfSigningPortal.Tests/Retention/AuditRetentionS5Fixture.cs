using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;
using OfficeSelfSigningPortal.Tests.Support;
using OfficeSelfSigningPortal.WebUI.Data;
using OfficeSelfSigningPortal.WorkerService.Data;
using OfficeSelfSigningPortal.WorkerService.Retention;
using OfficeSelfSigningPortal.WorkerService.Saga;
using Ossp.Audit;
using Testcontainers.PostgreSql;
using Xunit;

namespace OfficeSelfSigningPortal.Tests.Retention;

/// <summary>
/// Seam S5 (Persistenz) für die Audit-Retention Obergrenze 1 Jahr
/// (Ticket 38, REQ-19, F4). Eigener PostgreSQL-Testcontainer und eigene
/// Collection, weil die Audit-Retention am kontinuierlichen Tabellenanfang
/// löscht — ein geteilter Container mit den Blob-Retention-Tests würde
/// wegen der unvorhersehbaren Id-Vergabe zwingend zu false negatives
/// führen. Die Uhr ist fälschbar (<see cref="MutableTimeProvider"/>).
/// </summary>
public sealed class AuditRetentionS5Fixture : IAsyncLifetime
{
    private readonly PostgreSqlContainer _postgres = TestContainers.CreatePostgres();
    private readonly MutableTimeProvider _time = new();
    private ServiceProvider _services = null!;

    public string PortalConnectionString { get; private set; } = "";

    public string WorkerConnectionString { get; private set; } = "";

    /// <summary>Fälschbare Uhr — vor jedem Lauf vom Test auf den gewünschten Zeitpunkt setzen.</summary>
    public MutableTimeProvider Time => _time;

    public AsyncServiceScope CreateScope() => _services.CreateAsyncScope();

    public async Task InitializeAsync()
    {
        await _postgres.StartAsync();

        await _postgres.ExecScriptAsync("CREATE DATABASE worker;");

        PortalConnectionString = _postgres.GetConnectionString();
        WorkerConnectionString = new NpgsqlConnectionStringBuilder(_postgres.GetConnectionString())
        {
            Database = "worker",
        }.ConnectionString;

        var services = new ServiceCollection();
        services.AddLogging();
        services.AddAuditTrail(PortalConnectionString);
        services.AddDbContext<PortalDbContext>(options => options.UseNpgsql(PortalConnectionString));
        services.AddDbContext<WorkerDbContext>(options => options.UseNpgsql(WorkerConnectionString));
        services.AddSingleton<TimeProvider>(_time);
        services.AddSingleton<IRetentionBlobStore>(new PostgresRetentionBlobStore(PortalConnectionString));
        services.AddScoped<IAuditRetentionStore, PostgresAuditRetentionStore>();
        services.AddOptions<RetentionOptions>();
        services.AddScoped<RetentionExecutor>();
        _services = services.BuildServiceProvider(true);

        await using var scope = _services.CreateAsyncScope();
        await scope.ServiceProvider.GetRequiredService<AuditDbContext>().Database.MigrateAsync();
        await scope.ServiceProvider.GetRequiredService<PortalDbContext>().Database.MigrateAsync();
        await scope.ServiceProvider.GetRequiredService<WorkerDbContext>().Database.MigrateAsync();
    }

    public async Task DisposeAsync()
    {
        if (_services is not null)
        {
            await _services.DisposeAsync();
        }

        await _postgres.DisposeAsync();
    }

    /// <summary>Legt die Saga-Zeile eines signierten Vorgangs in der worker-DB an.</summary>
    public async Task SeedSignierteSagaAsync(
        Guid jobId, Guid artifactId, Guid signedArtifactId, DateTimeOffset receivedAt)
    {
        await using var scope = CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<WorkerDbContext>();
        db.SagaStates.Add(new AnalysisSagaState
        {
            CorrelationId = jobId,
            CurrentState = Ossp.Contracts.SagaStateNames.Signiert,
            SubmittedBy = "einreicher@example.test",
            ArtifactId = artifactId,
            ContentSha256 = new string('a', 64),
            OriginalFileName = "doku.xlsm",
            ContentType = "xlsm",
            FileSizeBytes = 1024,
            ReceivedAt = receivedAt,
            SignedArtifactId = signedArtifactId,
        });
        await db.SaveChangesAsync();
    }

    /// <summary>Legt Artefakt-Zeilen (Original und/oder signiert) in der portal-DB an.</summary>
    public async Task SeedArtifactsAsync(params Artifact[] artifacts)
    {
        await using var scope = CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<PortalDbContext>();
        db.Artifacts.AddRange(artifacts);
        await db.SaveChangesAsync();
    }

    /// <summary>
    /// Hängt einen Audit-Eintrag mit beliebigem Zeitstempel direkt an die Kette
    /// (Test-Seed — im Betrieb schreibt nur der <see cref="IAuditTrailWriter"/>).
    /// </summary>
    public async Task AppendAuditDirectAsync(
        Guid jobId,
        DateTimeOffset occurredAt,
        string category,
        string ereignis,
        string aktor,
        string? detail = null)
    {
        await using var scope = CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AuditDbContext>();

        var gestutzt = new DateTimeOffset(occurredAt.Ticks / 10 * 10, TimeSpan.Zero);
        var eintrag = new AuditEntry
        {
            JobId = jobId,
            OccurredAt = gestutzt,
            Category = category,
            Ereignis = ereignis,
            Aktor = aktor,
            Detail = detail,
            PrevHash = await db.AuditEntries
                .OrderByDescending(a => a.Id)
                .Select(a => a.EntryHash)
                .FirstOrDefaultAsync() ?? AuditHashChain.GenesisPrevHash,
        };
        eintrag.EntryHash = AuditHashChain.ComputeEntryHash(eintrag);
        db.AuditEntries.Add(eintrag);
        await db.SaveChangesAsync();
    }
}

[CollectionDefinition(AuditRetentionS5Collection.CollectionName)]
public sealed class AuditRetentionS5Collection : ICollectionFixture<AuditRetentionS5Fixture>
{
    public const string CollectionName = "Audit Retention S5";
}
