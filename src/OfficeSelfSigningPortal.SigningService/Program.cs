using MassTransit;
using Microsoft.EntityFrameworkCore;
using OfficeSelfSigningPortal.SigningService;
using OfficeSelfSigningPortal.SigningService.Data;
using OfficeSelfSigningPortal.SigningService.Messaging;
using Ossp.Contracts;

var builder = Host.CreateApplicationBuilder(args);

builder.AddServiceDefaults();

builder.Services.AddDbContext<SigningDbContext>(options =>
    options.UseNpgsql(builder.Configuration.GetConnectionString("signing")));

// Vorfalls-Protokoll des Guards über DbContext-Factory (siehe EfSigningIncidentWriter).
builder.Services.AddDbContextFactory<SigningDbContext>(options =>
    options.UseNpgsql(builder.Configuration.GetConnectionString("signing")));
builder.Services.AddSingleton<ISigningIncidentWriter, EfSigningIncidentWriter>();

// Defense-in-Depth (TM-19): Der Guard liest den Saga-Status read-only aus dem
// Saga-State-Store. Ohne konfigurierten Store startet der Dienst nicht — ein
// nicht verifizierbarer Signierauftrag darf nie stillschweigend akzeptiert werden.
var sagaStateConnectionString = builder.Configuration.GetConnectionString(SagaStateGuardOptions.ConnectionStringName)
    ?? throw new InvalidOperationException(
        $"Connection String '{SagaStateGuardOptions.ConnectionStringName}' fehlt — bitte Aspire-AppHost " +
        "(Referenz auf die Worker-Datenbank) oder Konfiguration prüfen.");
builder.Services.AddSingleton<ISagaStateReader>(_ => new PostgresSagaStateReader(sagaStateConnectionString));

var retryOptions = builder.Configuration.GetSection(OsspRetryOptions.SectionName)
    .Get<OsspRetryOptions>() ?? new OsspRetryOptions();

builder.Services.AddMassTransit(x =>
{
    x.AddSigningGuard();

    x.UsingRabbitMq((context, cfg) =>
    {
        var rabbitMqConnectionString = builder.Configuration.GetConnectionString("rabbitmq")
            ?? throw new InvalidOperationException(
                "Connection String 'rabbitmq' fehlt — bitte Aspire-AppHost oder Konfiguration prüfen.");
        cfg.Host(rabbitMqConnectionString);

        cfg.ReceiveEndpoint(QueueNames.SignMacroRequested, e =>
            SigningGuardBusConfiguration.ConfigureSigningGuardEndpoint(
                e, context, retryOptions.Limit, retryOptions.MinDelay, retryOptions.MaxDelay));
    });
});

builder.Services.AddHostedService<Worker>();

var app = builder.Build();

await app.RunAsync();
