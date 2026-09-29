using System.Reflection;
using Aspire.Hosting.ApplicationModel;

var builder = DistributedApplication.CreateBuilder(args);

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

// MailPit als Test-SMTP (REQ-21): UI auf 8025, SMTP auf 1025.
var mailpit = builder.AddContainer("mailpit", "axllent/mailpit", "latest")
    .WithHttpEndpoint(targetPort: 8025, name: "http")
    .WithEndpoint(targetPort: 1025, name: "smtp")
    .WithLifetime(ContainerLifetime.Persistent);

var webui = builder.AddProject<Projects.OfficeSelfSigningPortal_WebUI>("webui")
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
    .WithReference(workerDb)
    // Lesender Artefakt-Zugriff für den Scan (Ticket 05): Der WorkerService liest die
    // Blobs der Ingestion aus der Portal-DB (read-only, parametrisiert — kein EF-Pfad).
    .WithReference(portalDb)
    .WithReference(rabbitmq)
    .WaitFor(postgres)
    .WaitFor(rabbitmq);

var signingService = builder.AddProject<Projects.OfficeSelfSigningPortal_SigningService>("signingservice")
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
