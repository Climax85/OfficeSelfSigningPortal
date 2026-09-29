# Keycloak-Dev-Testuser anlegen (idempotent).
#
# Legt die Testuser des Dev-Realms an bzw. synchronisiert Passwort/Gruppen:
#   alice -> Einreicher, bob -> Einreicher+Bearbeiter, carol -> Admin
#
# Credentials stammen ausschließlich aus der lokalen Umgebung (REQ-24, TM-12) —
# dieselben Quellen, die der Aspire-AppHost verwendet:
#   - Admin:        Parameters__keycloak-admin / Parameters__keycloak-admin-password
#                   (User-Secrets des AppHost oder Umgebungsvariablen)
#   - User-Passwort: DEV_USER_PASSWORD (optional; sonst Zufall, einmalig ausgegeben)
#   - Keycloak-URL:  KEYCLOAK_URL (Aspire vergibt dynamische Ports — Wert aus dem
#                    Aspire-Dashboard, Endpunkt "keycloak" http)
#
# Aufruf (AppHost läuft):
#   pwsh ./tools/keycloak-dev-users.ps1 -KeycloakUrl http://localhost:<port>

[CmdletBinding()]
param(
    [string]$KeycloakUrl = [Environment]::GetEnvironmentVariable('KEYCLOAK_URL'),
    [string]$AdminUser = [Environment]::GetEnvironmentVariable('Parameters__keycloak-admin'),
    [string]$AdminPassword = [Environment]::GetEnvironmentVariable('Parameters__keycloak-admin-password'),
    [string]$DevPassword = [Environment]::GetEnvironmentVariable('DEV_USER_PASSWORD'),
    [string]$Realm = 'portal-dev'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not $KeycloakUrl) { throw 'Keycloak-URL fehlt — Parameter -KeycloakUrl oder Umgebungsvariable KEYCLOAK_URL setzen (Port aus dem Aspire-Dashboard).' }
if (-not $AdminUser -or -not $AdminPassword) { throw 'Keycloak-Admin-Credentials fehlen — Parameters__keycloak-admin / Parameters__keycloak-admin-password setzen (vgl. docs/development-setup.md).' }

$KeycloakUrl = $KeycloakUrl.TrimEnd('/')

# Initiales Testuser-Passwort: vorgegeben oder frisch generiert (einmalig sichtbar).
if (-not $DevPassword) {
    $bytes = New-Object byte[] 18
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    $DevPassword = [Convert]::ToBase64String($bytes).TrimEnd('=') + '!'
    Write-Host "Zufälliges Testuser-Passwort generiert (einmalig sichtbar): $DevPassword"
}

# Admin-Token (master realm, client admin-cli).
$tokenResponse = Invoke-RestMethod -Method Post `
    -Uri "$KeycloakUrl/realms/master/protocol/openid-connect/token" `
    -Body @{
        grant_type = 'password'
        client_id  = 'admin-cli'
        username   = $AdminUser
        password   = $AdminPassword
    }
$headers = @{ Authorization = "Bearer $($tokenResponse.access_token)" }
$admin = "$KeycloakUrl/admin/realms/$Realm"

# Gruppen-IDs auflösen (Realm-Import legt Einreicher/Bearbeiter/Admin an).
$groupIds = @{}
foreach ($group in (Invoke-RestMethod -Headers $headers -Uri "$admin/groups?max=100")) {
    $groupIds[$group.name] = $group.id
}
foreach ($required in 'Einreicher', 'Bearbeiter', 'Admin') {
    if (-not $groupIds.ContainsKey($required)) { throw "Gruppe '$required' fehlt im Realm '$Realm' — Realm-Import geprüft?" }
}

$users = @(
    @{ username = 'alice'; groups = @('Einreicher') },
    @{ username = 'bob'; groups = @('Einreicher', 'Bearbeiter') },
    @{ username = 'carol'; groups = @('Admin') }
)

foreach ($spec in $users) {
    $existing = Invoke-RestMethod -Headers $headers -Uri "$admin/users?username=$($spec.username)&exact=true"
    if ($existing.Count -eq 0) {
        Invoke-RestMethod -Method Post -Headers $headers -Uri "$admin/users" -Body (@{
            username = $spec.username
            enabled  = $true
        } | ConvertTo-Json) -ContentType 'application/json' | Out-Null
        $existing = Invoke-RestMethod -Headers $headers -Uri "$admin/users?username=$($spec.username)&exact=true"
        Write-Host "Angelegt: $($spec.username)"
    }
    else {
        Write-Host "Vorhanden: $($spec.username) (Passwort/Gruppen synchronisiert)"
    }

    $userId = $existing[0].id

    Invoke-RestMethod -Method Put -Headers $headers -Uri "$admin/users/$userId/reset-password" -Body (@{
        type      = 'password'
        value     = $DevPassword
        temporary = $false
    } | ConvertTo-Json) -ContentType 'application/json' | Out-Null

    foreach ($groupName in $spec.groups) {
        try {
            Invoke-RestMethod -Method Put -Headers $headers `
                -Uri "$admin/users/$userId/groups/$($groupIds[$groupName])" | Out-Null
        }
        catch {
            # 409 = bereits Mitglied — idempotenter Durchlauf.
            if ($_.Exception.Response.StatusCode -ne 409) { throw }
        }
    }
}

Write-Host "Fertig: $($users.Count) Testuser im Realm '$Realm' bereit (alice=Einreicher, bob=+Bearbeiter, carol=Admin)."
