using System.Net.Http.Headers;
using System.Reflection;
using Aspire.Hosting.ApplicationModel;
using Microsoft.Extensions.Configuration;

var builder = DistributedApplication.CreateBuilder(args);

// Deployment-Profil (Anhang E, AK-57): 'baseline' (Default) | 'hardened'. Wählbar per
// Kommandozeile (--Deployment:Profile=hardened), Umgebungsvariable (Deployment__Profile)
// oder appsettings.json — aufgelöst in dieser Priorität. Das Profil steuert Engine-Stages
// und Härtung des Deployments; das Schlüsselmanagement des SigningService bleibt davon
// unberührt (AppHost = Dev-Umgebung, AK-54).
var profileConfiguration = new ConfigurationBuilder()
    .AddJsonFile("appsettings.json", optional: true, reloadOnChange: false)
    .AddEnvironmentVariables()
    .AddCommandLine(args)
    .Build();
var deploymentProfile = profileConfiguration["Deployment:Profile"] ?? "baseline";
if (deploymentProfile is not ("baseline" or "hardened"))
{
    throw new InvalidOperationException(
        $"Unbekanntes Deployment-Profil '{deploymentProfile}' (Deployment:Profile, " +
        "gültig: baseline | hardened).");
}

// Dev-Credentials ausschließlich via Parameter (User-Secrets/Umgebungsvariablen) —
// niemals im Repository (REQ-24, TM-12). Setup: docs/development-setup.md
var postgresPassword = builder.AddParameter("postgres-password", secret: true);
var rabbitMqUser = builder.AddParameter("rabbitmq-user", secret: true);
var rabbitMqPassword = builder.AddParameter("rabbitmq-password", secret: true);
var keycloakAdmin = builder.AddParameter("keycloak-admin", secret: true);
var keycloakAdminPassword = builder.AddParameter("keycloak-admin-password", secret: true);

var postgres = builder.AddPostgres("postgres", password: postgresPassword)
    .WithDataVolume()
    .WithLifetime(ContainerLifetime.Persistent);

var portalDb = postgres.AddDatabase("portal");
var workerDb = postgres.AddDatabase("worker");
var signingDb = postgres.AddDatabase("signing");

var rabbitmq = builder.AddRabbitMQ("rabbitmq", userName: rabbitMqUser, password: rabbitMqPassword)
    .WithDataVolume()
    .WithLifetime(ContainerLifetime.Persistent);

// Keycloak als IdP-Container im Dev-Profil, Realm-Import aus dem Repository
// (Realm-Datei enthält keine Credentials).
var keycloakImportPath = typeof(Program).Assembly
    .GetCustomAttributes<AssemblyMetadataAttribute>()
    .Single(a => a.Key == "KeycloakImportPath")
    .Value!;

var keycloak = builder.AddContainer("keycloak", "quay.io/keycloak/keycloak", "latest")
    .WithEnvironment("KC_BOOTSTRAP_ADMIN_USERNAME", keycloakAdmin)
    .WithEnvironment("KC_BOOTSTRAP_ADMIN_PASSWORD", keycloakAdminPassword)
    .WithArgs("start-dev", "--import-realm")
    .WithHttpEndpoint(targetPort: 8080, name: "http")
    .WithBindMount(keycloakImportPath, "/opt/keycloak/data/import", isReadOnly: true)
    .WithLifetime(ContainerLifetime.Persistent);

// MailPit als Test-SMTP (REQ-21): UI auf 8025, SMTP auf 1025. STARTTLS mit
// auto-generiertem selbstsigniertem Zertifikat und Zwang — der Dev-Pfad durchläuft
// damit denselben TLS-Zwang wie der Betrieb (TM-11); die Zertifikatsprüfung setzt
// der WorkerService nur für diesen Container per Smtp:DisableCertificateValidation
// außer Kraft (Dev-Only, siehe SmtpOptions).
var mailpit = builder.AddContainer("mailpit", "axllent/mailpit", "latest")
    .WithHttpEndpoint(targetPort: 8025, name: "http")
    .WithEndpoint(targetPort: 1025, name: "smtp")
    .WithEnvironment("MP_SMTP_TLS_CERT", "sans:mailpit")
    .WithEnvironment("MP_SMTP_TLS_KEY", "sans:mailpit")
    .WithEnvironment("MP_SMTP_REQUIRE_STARTTLS", "true")
    .WithLifetime(ContainerLifetime.Persistent);

// Dev-Port fest verdrahtet: Keycloak validiert redirect_uri strikt (Port-
// Wildcards werden von Keycloak 26 nicht unterstützt, Suffix-Globs nur am
// Pfadende) — App-Port und Realm-Konfiguration müssen deckungsgleich sein.
var webui = builder.AddProject<Projects.OfficeSelfSigningPortal_WebUI>("webui")
    .WithHttpEndpoint(port: 5000, name: "http")
    // Dev-Umgebung: s. workerservice — ohne Development fehlt blazor.web.js (404).
    .WithEnvironment("DOTNET_ENVIRONMENT", "Development")
    .WithReference(portalDb)
    // Ticket 07: Die Review-API liest offene Vorgänge read-only aus dem
    // Saga-State-Store (kein Schreibpfad, parametrisiertes SQL wie im SigningService).
    .WithReference(workerDb, connectionName: "sagastate")
    .WithReference(rabbitmq)
    .WithEnvironment("PortalAuth__Authority",
        ReferenceExpression.Create($"{keycloak.GetEndpoint("http")}/realms/portal-dev"))
    // Der Dev-Keycloak-Endpoint ist http (Container-Interna); der sichere Default
    // (RequireHttpsMetadata=true) bleibt unverändert und wird hier nur fürs Dev-Profil umgeschaltet.
    .WithEnvironment("PortalAuth__RequireHttpsMetadata", "false")
    .WaitFor(postgres)
    .WaitFor(rabbitmq);

var workerService = builder.AddProject<Projects.OfficeSelfSigningPortal_WorkerService>("workerservice")
    // Dev-Umgebung: sonst lädt der Host die Static Web Assets (u. a. blazor.web.js)
    // nicht (UseStaticWebAssets läuft nur in Development) und wwwroot 404-et.
    .WithEnvironment("DOTNET_ENVIRONMENT", "Development")
    .WithReference(workerDb)
    // Lesender Artefakt-Zugriff für den Scan (Ticket 05): Der WorkerService liest die
    // Blobs der Ingestion aus der Portal-DB (read-only, parametrisiert — kein EF-Pfad).
    .WithReference(portalDb)
    .WithReference(rabbitmq)
    // E-Mail-Benachrichtigungen (Ticket 10, REQ-21/AK-56): Versand durch die Saga über
    // MailPit — Verbindung, Portal-Link und Dev-Empfänger für das Security-Team.
    .WithEnvironment("Smtp__Host", mailpit.GetEndpoint("smtp").Property(EndpointProperty.Host))
    .WithEnvironment("Smtp__Port", mailpit.GetEndpoint("smtp").Property(EndpointProperty.Port))
    .WithEnvironment("Smtp__From", "portal@ossp.local")
    .WithEnvironment("Smtp__DisableCertificateValidation", "true")
    .WithEnvironment("Notifications__PortalBaseUrl",
        ReferenceExpression.Create($"http://{webui.GetEndpoint("http").Property(EndpointProperty.Host)}:{webui.GetEndpoint("http").Property(EndpointProperty.Port)}"))
    .WithEnvironment("Notifications__SecurityTeamAddress", "security-team@ossp.local")
    .WaitFor(postgres)
    .WaitFor(rabbitmq)
    .WaitFor(mailpit);

if (deploymentProfile == "hardened")
{
    // Anhang E/AK-57: Profil hardened aktiviert die AMSI-Bridge-Stage (REQ-12,
    // ADR-0004). Die Brücke ist ein eigenes Projekt (Ossp.AmsiScanBridge) und
    // wird im Dev-Profil vom AppHost gestartet; im Produktionsbetrieb läuft
    // sie auf einem dedizierten Windows-Host außerhalb Aspire (F5, ADR-0004).
    //
    // Beide Konfigurationspunkte sind als Aspire-Parameter umgesetzt — der
    // AppHost verweigert ohne Angabe den Start (fail-fast, CONVENTIONS §5):
    //   amsi-bridge-url   — Bridge-URL, die der WorkerService als HTTP-Endpoint nutzt
    //   amsi-bridge-token — Shared-Secret für die X-Amsi-Bridge-Token-Authentisierung
    //
    // Das Token wird sowohl in die Brücke als auch in den WorkerService
    // eingespielt (symmetrisches Shared-Secret, SF-04-Backlog F5). Ausfall/
    // Timeout der Bridge führt in der Policy zu Inconclusive + Review-Pflicht
    // (TM-15/AK-26) — niemals Auto-Signing.
    var amsiBridgeUrl = builder.AddParameter("amsi-bridge-url");
    var amsiBridgeToken = builder.AddParameter("amsi-bridge-token", secret: true);
    var amsiBridge = builder.AddProject<Projects.Ossp_AmsiScanBridge>("amsiscanbridge")
        .WithEnvironment("AmsiScanBridge__Token", amsiBridgeToken)
        .WithEnvironment("AmsiScanBridge__ListenUrl", "http://127.0.0.1:5101");

    workerService = workerService
        .WithEnvironment("Scanning__Engines__AmsiEnabled", "true")
        .WithEnvironment("Scanning__Engines__AmsiBridgeUrl", amsiBridgeUrl)
        .WithEnvironment("Scanning__Engines__AmsiBridgeToken", amsiBridgeToken)
        // Härtung (REQ-12/REQ-25, AK-57): WorkerService darf die Brücke nur über
        // deren Loopback-Endpoint erreichen. Im Dev-Betrieb übernimmt Aspire die
        // Service-Discovery; im Produktionsbetrieb ist die Bridge-URL explizit
        // auf den Loopback des Windows-Hosts gesetzt — der WorkerService selbst
        // läuft im internen Container-Netz ohne externen Ausgang.
        .WaitFor(amsiBridge);
}

var signingService = builder.AddProject<Projects.OfficeSelfSigningPortal_SigningService>("signingservice")
    // Dev-Umgebung: s. workerservice — Static Web Assets erfordern Development.
    .WithEnvironment("DOTNET_ENVIRONMENT", "Development")
    // Dev-Profil: LocalDevKeyProvider ist ausschließlich hier zulässig (AK-54, TC-35).
    .WithEnvironment("Deployment__Profile", "dev")
    .WithReference(signingDb)
    // TM-19: Der Guard verifiziert den Saga-Status read-only gegen den Saga-State-Store.
    .WithReference(workerDb, connectionName: "sagastate")
    // Ticket 06: Guard-Ablehnungen (AK-39) schreiben in den konsolidierten Audit-Trail.
    .WithReference(portalDb)
    .WithReference(rabbitmq)
    .WaitFor(postgres)
    .WaitFor(rabbitmq);

builder.Build().Run();
