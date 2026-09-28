using MassTransit;
using Microsoft.EntityFrameworkCore;
using OfficeSelfSigningPortal.WorkerService;
using OfficeSelfSigningPortal.WorkerService.Data;
using OfficeSelfSigningPortal.WorkerService.Messaging;
using OfficeSelfSigningPortal.WorkerService.Saga;
using Ossp.Contracts;

var builder = Host.CreateApplicationBuilder(args);

builder.AddServiceDefaults();

builder.Services.AddDbContext<WorkerDbContext>(options =>
    options.UseNpgsql(builder.Configuration.GetConnectionString("worker")));

// Saga-Audit: synchroner Writer über DbContext-Factory (siehe EfSagaAuditWriter).
builder.Services.AddDbContextFactory<WorkerDbContext>(options =>
    options.UseNpgsql(builder.Configuration.GetConnectionString("worker")));
builder.Services.AddSingleton<ISagaAuditWriter, EfSagaAuditWriter>();

builder.Services.AddOptions<OsspRetryOptions>().BindConfiguration(OsspRetryOptions.SectionName);

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

            // Dead-Letter-Pfad des Scanner-Endpunkts (Consumer selbst verdrahtet Ticket 05;
            // bis dahin bindet der Endpoint leer und greift, sobald der Scanner existiert).
            cfg.ReceiveEndpoint(QueueNames.ScanRequestedError, e =>
                AnalysisSagaBusConfiguration.ConfigureScanDeadLetterEndpoint(e, context));
        });
    }
});

builder.Services.AddHostedService<Worker>();

var app = builder.Build();

await app.RunAsync();
