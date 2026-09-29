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

**Wichtig:** User-Secrets lädt der AppHost nur mit `DOTNET_ENVIRONMENT=Development`
(bzw. `ASPNETCORE_ENVIRONMENT=Development`). Das stellt `Properties/launchSettings.json`
beim Start über `dotnet run`/VS sicher. Ohne Development-Umgebung bleiben die
User-Secrets wirkungslos, die Parameter werden als leer angesehen und Aspire
generiert pro Start neue Zufallswerte — bei den persistenten Containern
(`WithLifetime(Persistent)` + Data-Volumes) führt ein Passwortwechsel dann zu
Auth-Fehlern gegen die alten Volumes (Volume ggf. zurücksetzen: `docker volume rm
apphost-<hash>-postgres-data` o.ä., Dev-Daten gehen dabei verloren).

**Dev-Ausnahme Transportverschlüsselung (OP-05):** Der gesamte lokale Dev-Stack
läuft bewusst unverschlüsselt auf localhost (HTTP-Endpunkte, exakte
`http://localhost:5000/signin-oidc` im Keycloak-Dev-Realm,
`ASPIRE_ALLOW_UNSECURED_TRANSPORT` im AppHost-Profil). Das Threat Model verlangt
TLS 1.2+ (OP-05) für betriebene Umgebungen — für den lokalen Aspire-Dev-Stack
gilt diese Ausnahme explizit; betriebliche Konfigurationen müssen TLS aktivieren
und dürfen die Dev-Realm-Datei nicht verwenden.

Das Keycloak-Dev-Realm (`keycloak/realm.json`) enthält absichtlich **keine** Nutzer
oder Credentials — Testuser legt das idempotente Skript an. Es liest Admin-
Credentials und (nach dem ersten AppHost-Start) die Keycloak-URL aus den
**User-Secrets des AppHost**; nichts davon landet im Repository (REQ-24):

```powershell
./tools/keycloak-dev-users.ps1
# optional mit explizitem Passwort für alle Testuser:
$env:DEV_USER_PASSWORD = "<initiales-passwort>"   # sonst Zufall (einmalig ausgegeben)
```

Auflösung je Wert (Parameter > Umgebung > User-Secrets): `-KeycloakUrl` /
`KEYCLOAK_URL` / User-Secret `Resources:keycloak:http:port`; Admin aus
`Parameters:keycloak-admin[-password]`. Legt synchronisiert an: `alice`
(Einreicher), `bob` (Einreicher + Bearbeiter), `carol` (Admin). Wiederholte
Aufrufe aktualisieren Passwort/Gruppen.

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
