# Development Setup

Lokales Setup der Lösung (Windows/Linux/macOS mit Docker).

## Voraussetzungen

- .NET 10 SDK (`dotnet --version` ≥ 10.0.100)
- Docker (für Aspire-Container und Testcontainers)

## Dev-Credentials (REQ-24, TM-12)

Dev-Credentials liegen **ausschließlich** in User-Secrets oder Umgebungsvariablen —
niemals im Repository. Die Aspire-Parameter werden über Umgebungsvariablen im Format
`Parameters__<name>` bereitgestellt (auflösungsstärkste Quelle; funktioniert identisch
lokal und in der CI). Einmalig pro Shell (Dev-Werte sind maschinenlokal, nicht im Repo):

```bash
# Linux/macOS
export Parameters__postgres-password="<dev-pw>"
export Parameters__rabbitmq-user="<dev-user>"
export Parameters__rabbitmq-password="<dev-pw>"
export Parameters__keycloak-admin="<dev-user>"
export Parameters__keycloak-admin-password="<dev-pw>"

# Windows (PowerShell)
$env:Parameters__postgres-password = "<dev-pw>"
$env:Parameters__rabbitmq-user = "<dev-user>"
$env:Parameters__rabbitmq-password = "<dev-pw>"
$env:Parameters__keycloak-admin = "<dev-user>"
$env:Parameters__keycloak-admin-password = "<dev-pw>"
```

Alternative: `dotnet user-secrets set --project src/OfficeSelfSigningPortal.AppHost
"Parameters:<name>" "<wert>"` — Aspire löst nicht gesetzte Parameter interaktiv nach
(ggf. Prompt beim AppHost-Start).

Das Keycloak-Dev-Realm (`keycloak/realm.json`) enthält absichtlich **keine** Nutzer
oder Credentials — Testuser werden in einem Folgeticket angelegt.

## AppHost starten

```bash
dotnet run --project src/OfficeSelfSigningPortal.AppHost
```

Startet: WebUI, WorkerService, SigningService sowie PostgreSQL (Datenbanken
`portal`, `worker`, `signing`), RabbitMQ, Keycloak (inkl. Realm-Import) und MailPit
als Container. Die Dashboard-URL zeigt Ports und Logs.

## EF Core

Pro Dienst existiert ein DbContext mit Design-Time-Factory und Migrations:

| Dienst | DbContext | Connection String |
|---|---|---|
| WebUI | `PortalDbContext` | `portal` |
| WorkerService | `WorkerDbContext` | `worker` |
| SigningService | `SigningDbContext` | `signing` |

Neue Migration (Connection String per User-Secret oder Umgebungsvariable
`ConnectionStrings:<name>`, niemals committen):

```bash
dotnet ef migrations add <Name> --project src/OfficeSelfSigningPortal.WebUI --context PortalDbContext
```

## Tests

```bash
# Schnelle Suite (ohne Integrationstests)
dotnet test --filter "Category!=Integration"

# Integrationstests (Testcontainers: Docker erforderlich)
dotnet test --filter "Category=Integration"
```

Lokale Integritätsprüfung vor dem Commit:

```bash
dotnet build && dotnet test --filter "Category!=Integration"
```
