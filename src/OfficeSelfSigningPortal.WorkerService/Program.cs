using MassTransit;
using Microsoft.EntityFrameworkCore;
using OfficeSelfSigningPortal.WorkerService;
using OfficeSelfSigningPortal.WorkerService.Data;
using OfficeSelfSigningPortal.WorkerService.Messaging;
using OfficeSelfSigningPortal.WorkerService.Notifications;
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

// E-Mail-Benachrichtigungen (Ticket 10, REQ-08/REQ-21): optional — ohne Smtp:Host
// ist der Versandpfad deaktiviert und läuft als NullEmailSender still mit
// (AK-21, TC-42: kein E-Mail-Fehler, keine Blockade). Mit Host gilt TLS-Zwang
// (TM-11); DisableCertificateValidation ausschließlich für den lokalen
// MailPit-Dev-Container (selbstsigniert).
builder.Services.AddOptions<SmtpOptions>().BindConfiguration(SmtpOptions.SectionName);
builder.Services.AddOptions<NotificationOptions>().BindConfiguration(NotificationOptions.SectionName);
var smtpOptions = builder.Configuration.GetSection(SmtpOptions.SectionName).Get<SmtpOptions>() ?? new SmtpOptions();
if (string.IsNullOrWhiteSpace(smtpOptions.Host))
{
    builder.Services.AddSingleton<IEmailSender, NullEmailSender>();
}
else
{
    builder.Services.AddSingleton<IEmailSender, SmtpEmailSender>();
}

// Scan-Orchestrator (Ticket 05, Seam S3, REQ-12): Scoring + Engine-Stages + Blob-Zugriff.
// ClamAV-Host/AMSI-Bridge werden betrieblich konfiguriert (Anhang E); nicht konfigurierte
// Stages melden Absent statt auszufallen (AK-46).
builder.Services.AddOptions<ScoringOptions>().BindConfiguration(ScoringOptions.SectionName);
builder.Services.AddOptions<ScanEnginesOptions>().BindConfiguration(ScanEnginesOptions.SectionName);
// Concurrency-Limit / Prefetch-Count am Scan-Endpoint (Ticket 37, TM-14, SF-03).
builder.Services.AddOptions<ScanExecutionOptions>().BindConfiguration(ScanExecutionOptions.SectionName);
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
// bis zur Audit-Retention-Obergrenze (Default 1 Jahr, Ticket 38) append-only
// bestehen. Beide Löschpfade laufen im selben Executor-Lauf; sanctioned
// Audit-Lösch-Grenzen werden in der `audit_chain_checkpoints`-Tabelle
// festgehalten.
builder.Services.AddOptions<RetentionOptions>().BindConfiguration(RetentionOptions.SectionName);
builder.Services.AddSingleton(TimeProvider.System);
builder.Services.AddScoped<RetentionExecutor>();
builder.Services.AddSingleton<IRetentionBlobStore>(_ => new PostgresRetentionBlobStore(portalConnectionString));
builder.Services.AddScoped<IAuditRetentionStore, PostgresAuditRetentionStore>();
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
        var scanExecutionOptionsInMem = builder.Configuration.GetSection(ScanExecutionOptions.SectionName)
            .Get<ScanExecutionOptions>() ?? new ScanExecutionOptions();
        x.UsingInMemory((context, cfg) =>
        {
            cfg.ReceiveEndpoint(QueueNames.AnalysisSaga, e =>
                AnalysisSagaBusConfiguration.ConfigureSagaEndpoint(e, context, retryOptions, useEntityFrameworkOutbox: false));
            cfg.ReceiveEndpoint(QueueNames.ScanRequested, e =>
                AnalysisSagaBusConfiguration.ConfigureScanExecutionEndpoint(e, context, retryOptions, scanExecutionOptionsInMem));
            cfg.ReceiveEndpoint(QueueNames.ScanRequestedError, e =>
                AnalysisSagaBusConfiguration.ConfigureScanDeadLetterEndpoint(e, context));
            cfg.ReceiveEndpoint(QueueNames.EmailBenachrichtigung, e =>
                AnalysisSagaBusConfiguration.ConfigureEmailNotificationEndpoint(e, context, retryOptions));
        });
    }
    else
    {
        var rabbitMqConnectionString = builder.Configuration.GetConnectionString("rabbitmq")
            ?? throw new InvalidOperationException(
                "Connection String 'rabbitmq' fehlt — bitte Aspire-AppHost oder Konfiguration prüfen.");
        var scanExecutionOptions = builder.Configuration.GetSection(ScanExecutionOptions.SectionName)
            .Get<ScanExecutionOptions>() ?? new ScanExecutionOptions();
        x.UsingRabbitMq((context, cfg) =>
        {
            cfg.Host(rabbitMqConnectionString);

            cfg.ReceiveEndpoint(QueueNames.AnalysisSaga, e =>
                AnalysisSagaBusConfiguration.ConfigureSagaEndpoint(e, context, retryOptions, useEntityFrameworkOutbox: true));

            // Scanner-Ausführung: Blob lesen, Engines laufen lassen, ScanCompleted publizieren.
            // Retry-Policy identisch mit dem DLQ-Pfad (ossp.scan-requested_error, TC-16).
            cfg.ReceiveEndpoint(QueueNames.ScanRequested, e =>
                AnalysisSagaBusConfiguration.ConfigureScanExecutionEndpoint(e, context, retryOptions, scanExecutionOptions));

            cfg.ReceiveEndpoint(QueueNames.ScanRequestedError, e =>
                AnalysisSagaBusConfiguration.ConfigureScanDeadLetterEndpoint(e, context));

            cfg.ReceiveEndpoint(QueueNames.EmailBenachrichtigung, e =>
                AnalysisSagaBusConfiguration.ConfigureEmailNotificationEndpoint(e, context, retryOptions));
        });
    }
});

builder.Services.AddHostedService<Worker>();

var app = builder.Build();

var startupLogger = app.Services.GetRequiredService<ILoggerFactory>().CreateLogger("OfficeSelfSigningPortal.WorkerService.Startup");
startupLogger.LogInformation(
    string.IsNullOrWhiteSpace(smtpOptions.Host)
        ? "E-Mail-Benachrichtigungen deaktiviert (kein Smtp:Host konfiguriert, AK-21)."
        : "E-Mail-Benachrichtigungen aktiv über {SmtpHost}:{SmtpPort} (TLS erzwungen, TM-11).",
    smtpOptions.Host,
    smtpOptions.Port);

await app.RunAsync();
