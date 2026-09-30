using MassTransit;
using Microsoft.EntityFrameworkCore;
using OfficeSelfSigningPortal.WorkerService;
using OfficeSelfSigningPortal.WorkerService.Data;
using OfficeSelfSigningPortal.WorkerService.Messaging;
using OfficeSelfSigningPortal.WorkerService.Retention;
using OfficeSelfSigningPortal.WorkerService.Saga;
using OfficeSelfSigningPortal.WorkerService.Scanning;
using OfficeSelfSigningPortal.WorkerService.Scanning.Vba;
using Ossp.Audit;
using Ossp.Contracts;

var builder = Host.CreateApplicationBuilder(args);

builder.AddServiceDefaults();

builder.Services.AddDbContext<WorkerDbContext>(options =>
    options.UseNpgsql(builder.Configuration.GetConnectionString("worker")));

// portal-DB-Verbindung (Artefakt-Speicher lesen, Audit-Trail schreiben).
var portalConnectionString = builder.Configuration.GetConnectionString("portal")
    ?? throw new InvalidOperationException(
        "Connection String 'portal' fehlt — der Scan benötigt lesenden Zugriff auf den Artefakt-Speicher der Ingestion (Aspire-AppHost prüfen).");

// Saga-Audit: Übergänge in den konsolidierten Audit-Trail (Ticket 06, REQ-18).
builder.Services.AddAuditTrail(portalConnectionString);
builder.Services.AddSingleton<ISagaAuditWriter, SagaAuditTrailWriter>();

builder.Services.AddOptions<OsspRetryOptions>().BindConfiguration(OsspRetryOptions.SectionName);

// Scan-Orchestrator (Ticket 05, Seam S3, REQ-12): Scoring + Engine-Stages + Blob-Zugriff.
// ClamAV-Host/AMSI-Bridge werden betrieblich konfiguriert (Anhang E); nicht konfigurierte
// Stages melden Absent statt auszufallen (AK-46).
builder.Services.AddOptions<ScoringOptions>().BindConfiguration(ScoringOptions.SectionName);
builder.Services.AddOptions<ScanEnginesOptions>().BindConfiguration(ScanEnginesOptions.SectionName);
builder.Services.AddSingleton<VbaProjectExtractor>();
builder.Services.AddSingleton<HeuristicScanEngine>();
builder.Services.AddSingleton<IScanEngine, YaraScanEngine>();
builder.Services.AddSingleton<IScanEngine, ClamAvScanEngine>();

var scanEngines = builder.Configuration.GetSection(ScanEnginesOptions.SectionName)
    .Get<ScanEnginesOptions>() ?? new ScanEnginesOptions();
if (scanEngines.AmsiEnabled)
{
    // Profil hardened (ADR-0004): AMSI-Stage registrieren; die Ablauf-Deadline setzt
    // der Orchestrator per CancellationToken (Timeout.InfiniteTimeSpan am Client).
    builder.Services.AddHttpClient<AmsiScanEngine>(client => client.Timeout = Timeout.InfiniteTimeSpan);
    builder.Services.AddSingleton<IScanEngine>(sp => sp.GetRequiredService<AmsiScanEngine>());
}

builder.Services.AddSingleton<ScanOrchestrator>();

builder.Services.AddSingleton<IArtifactBlobStore>(_ => new PostgresArtifactBlobStore(portalConnectionString));

// Retention-Job (Ticket 11, REQ-19): löscht Original- und Signatur-Blobs nach der
// konfigurierbaren Frist (Default 90 Tage) ab Signierung; Audit-Bestand bleibt
// append-only bestehen. Der Blob-Löschpfad ist bewusst auf diesen Job beschränkt.
builder.Services.AddOptions<RetentionOptions>().BindConfiguration(RetentionOptions.SectionName);
builder.Services.AddSingleton(TimeProvider.System);
builder.Services.AddScoped<RetentionExecutor>();
builder.Services.AddSingleton<IRetentionBlobStore>(_ => new PostgresRetentionBlobStore(portalConnectionString));
builder.Services.AddHostedService<RetentionJob>();

// Transportwahl: Produktion/Aspire = RabbitMQ; Test-Suites setzen OsspBus:Transport=InMemory.
var transport = builder.Configuration.GetValue<string>("OsspBus:Transport") ?? "RabbitMQ";
var retryOptions = builder.Configuration.GetSection(OsspRetryOptions.SectionName)
    .Get<OsspRetryOptions>() ?? new OsspRetryOptions();

builder.Services.AddMassTransit(x =>
{
    x.AddAnalysisSaga(useEntityFrameworkRepository: true);

    // Outbox statt direktem Publish (REQ-11, TM-06): Saga-Publishes committen
    // atomar mit dem Zustandsübergang.
    x.AddEntityFrameworkOutbox<WorkerDbContext>(o =>
    {
        o.UsePostgres();
        o.QueryDelay = TimeSpan.FromSeconds(5);
    });

    if (transport.Equals("InMemory", StringComparison.OrdinalIgnoreCase))
    {
        x.UsingInMemory((context, cfg) =>
        {
            cfg.ReceiveEndpoint(QueueNames.AnalysisSaga, e =>
                AnalysisSagaBusConfiguration.ConfigureSagaEndpoint(e, context, retryOptions, useEntityFrameworkOutbox: false));
            cfg.ReceiveEndpoint(QueueNames.ScanRequested, e =>
                AnalysisSagaBusConfiguration.ConfigureScanExecutionEndpoint(e, context, retryOptions));
            cfg.ReceiveEndpoint(QueueNames.ScanRequestedError, e =>
                AnalysisSagaBusConfiguration.ConfigureScanDeadLetterEndpoint(e, context));
        });
    }
    else
    {
        var rabbitMqConnectionString = builder.Configuration.GetConnectionString("rabbitmq")
            ?? throw new InvalidOperationException(
                "Connection String 'rabbitmq' fehlt — bitte Aspire-AppHost oder Konfiguration prüfen.");
        x.UsingRabbitMq((context, cfg) =>
        {
            cfg.Host(rabbitMqConnectionString);

            cfg.ReceiveEndpoint(QueueNames.AnalysisSaga, e =>
                AnalysisSagaBusConfiguration.ConfigureSagaEndpoint(e, context, retryOptions, useEntityFrameworkOutbox: true));

            // Scanner-Ausführung: Blob lesen, Engines laufen lassen, ScanCompleted publizieren.
            // Retry-Policy identisch mit dem DLQ-Pfad (ossp.scan-requested_error, TC-16).
            cfg.ReceiveEndpoint(QueueNames.ScanRequested, e =>
                AnalysisSagaBusConfiguration.ConfigureScanExecutionEndpoint(e, context, retryOptions));

            cfg.ReceiveEndpoint(QueueNames.ScanRequestedError, e =>
                AnalysisSagaBusConfiguration.ConfigureScanDeadLetterEndpoint(e, context));
        });
    }
});

builder.Services.AddHostedService<Worker>();

var app = builder.Build();

await app.RunAsync();
