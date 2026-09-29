using MassTransit;
using Microsoft.EntityFrameworkCore;
using OfficeSelfSigningPortal.SigningService;
using OfficeSelfSigningPortal.SigningService.Data;
using OfficeSelfSigningPortal.SigningService.Keys;
using OfficeSelfSigningPortal.SigningService.Messaging;
using OfficeSelfSigningPortal.SigningService.Signing;
using Ossp.Audit;
using Ossp.Contracts;

var builder = Host.CreateApplicationBuilder(args);

builder.AddServiceDefaults();

builder.Services.AddDbContext<SigningDbContext>(options =>
    options.UseNpgsql(builder.Configuration.GetConnectionString("signing")));

// Audit-Trail (REQ-18): Guard-Ablehnungen (AK-39) und Signier-Evidenz (TM-08) schreiben
// append-only in die gemeinsame SHA-256-Hash-Kette der portal-DB (Ticket 06).
var portalConnectionString = builder.Configuration.GetConnectionString("portal")
    ?? throw new InvalidOperationException(
        "Connection String 'portal' fehlt — bitte Aspire-AppHost (Referenz auf die Portal-Datenbank) oder Konfiguration prüfen.");
builder.Services.AddAuditTrail(portalConnectionString);

// Artefakt-Blobs (Signier-Input + Ablage des signierten Blobs, TC-27): Zugriff auf die
// Artefakt-Tabelle der Portal-DB (fremdes Schema, parametrisiertes SQL — CONVENTIONS §6).
builder.Services.AddSingleton<IArtifactBlobAccess>(
    _ => new PostgresArtifactBlobAccess(portalConnectionString));

// Defense-in-Depth (TM-19): Der Guard liest den Saga-Status read-only aus dem
// Saga-State-Store. Ohne konfigurierten Store startet der Dienst nicht — ein
// nicht verifizierbarer Signierauftrag darf nie stillschweigend akzeptiert werden.
var sagaStateConnectionString = builder.Configuration.GetConnectionString(SagaStateGuardOptions.ConnectionStringName)
    ?? throw new InvalidOperationException(
        $"Connection String '{SagaStateGuardOptions.ConnectionStringName}' fehlt — bitte Aspire-AppHost " +
        "(Referenz auf die Worker-Datenbank) oder Konfiguration prüfen.");
builder.Services.AddSingleton<ISagaStateReader>(_ => new PostgresSagaStateReader(sagaStateConnectionString));

// Signer (AK-50, ADR-0003): VbaProjectSigner (Primär, managed, Linux) oder
// WindowsSigningAgent (Fallback — Betriebsverdrahtung).
var signerName = builder.Configuration["Signing:Signer"] ?? "VbaProjectSigner";
builder.Services.AddSingleton<IVbaProjectSigner>(signerName switch
{
    "VbaProjectSigner" => new VbaProjectSigner(),
    "WindowsSigningAgent" => new WindowsSigningAgentSigner(),
    _ => throw new InvalidOperationException(
        $"Unbekannter Signing:Signer '{signerName}' (gültig: VbaProjectSigner | WindowsSigningAgent)."),
});

// Key-Provider (AK-53/AK-54, REQ-15): Auswahl per Konfiguration; LocalDev nur im Dev-Profil.
builder.Services.AddCodeSigningKeyProvider(builder.Configuration);

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

var app = builder.Build();

await app.RunAsync();
