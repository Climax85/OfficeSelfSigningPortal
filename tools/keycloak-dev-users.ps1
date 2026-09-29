# Keycloak-Dev-Testuser anlegen (idempotent).
#
# Legt die Testuser des Dev-Realms an bzw. synchronisiert Passwort/Gruppen:
#   alice -> Einreicher, bob -> Einreicher+Bearbeiter, carol -> Admin
#
# Auflösung der Werte (jeweils Parameter > Umgebung > User-Secrets des AppHost):
#   - Keycloak-URL:    -KeycloakUrl / KEYCLOAK_URL / User-Secret
#                      "Resources:keycloak:http:port" (von Aspire persistiert —
#                      existiert erst nach dem ersten AppHost-Start)
#   - Admin:           -AdminUser -AdminPassword /
#                      Parameters__keycloak-admin[-password] /
#                      User-Secrets "Parameters:keycloak-admin[-password]"
#   - User-Passwort:   -DevPassword / DEV_USER_PASSWORD — sonst Zufall (einmalig sichtbar)
#
# Credentials liegen ausschließlich lokal (User-Secrets des AppHost, REQ-24, TM-12) —
# nicht im Repository, nicht in diesem Skript.
#
# Aufruf (AppHost läuft):
#   ./tools/keycloak-dev-users.ps1

[CmdletBinding()]
param(
    [string]$KeycloakUrl,
    [string]$AdminUser,
    [string]$AdminPassword,
    [string]$DevPassword = [Environment]::GetEnvironmentVariable('DEV_USER_PASSWORD'),
    [string]$Realm = 'portal-dev'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$appHostProject = Resolve-Path (Join-Path $PSScriptRoot '..\src\OfficeSelfSigningPortal.AppHost')

# User-Secrets des AppHost einmalig einlesen (dotnet user-secrets list --json).
function Get-UserSecrets {
    $raw = & dotnet user-secrets list --project $appHostProject --json 2>$null
    if ($LASTEXITCODE -ne 0 -or -not $raw) { return @{} }
    # dotnet rahmt das JSON mit //BEGIN ... //END ein — Blockgrenzen suchen.
    $jsonStart = 0
    while ($jsonStart -lt $raw.Count -and $raw[$jsonStart] -notmatch '\{') {
        $jsonStart++
    }
    $jsonEnd = $jsonStart
    while ($jsonEnd -lt $raw.Count -and $raw[$jsonEnd] -notmatch '^\s*\}') {
        $jsonEnd++
    }
    if ($jsonStart -ge $raw.Count -or $jsonEnd -ge $raw.Count) { return @{} }
    try {
        $parsed = [string]::Join([Environment]::NewLine, [string[]]$raw[$jsonStart..$jsonEnd]) | ConvertFrom-Json
        $result = @{}
        foreach ($property in $parsed.PSObject.Properties) {
            $result[$property.Name] = [string]$property.Value
        }
        return $result
    }
    catch {
        return @{}
    }
}

$userSecrets = Get-UserSecrets

if (-not $KeycloakUrl) {
    $KeycloakUrl = [Environment]::GetEnvironmentVariable('KEYCLOAK_URL')
}
if (-not $KeycloakUrl -and $userSecrets.ContainsKey('Resources:keycloak:http:port')) {
    $KeycloakUrl = "http://localhost:$($userSecrets['Resources:keycloak:http:port'])"
}
if (-not $KeycloakUrl) {
    throw 'Keycloak-URL nicht bestimmbar — -KeycloakUrl oder KEYCLOAK_URL setzen (Port steht im Aspire-Dashboard; nach dem ersten AppHost-Start persistiert in den User-Secrets).'
}

if (-not $AdminUser) {
    $AdminUser = [Environment]::GetEnvironmentVariable('Parameters__keycloak-admin')
}
if (-not $AdminUser -and $userSecrets.ContainsKey('Parameters:keycloak-admin')) {
    $AdminUser = $userSecrets['Parameters:keycloak-admin']
}
if (-not $AdminPassword) {
    $AdminPassword = [Environment]::GetEnvironmentVariable('Parameters__keycloak-admin-password')
}
if (-not $AdminPassword -and $userSecrets.ContainsKey('Parameters:keycloak-admin-password')) {
    $AdminPassword = $userSecrets['Parameters:keycloak-admin-password']
}
if (-not $AdminUser -or -not $AdminPassword) {
    throw 'Keycloak-Admin-Credentials nicht gefunden — User-Secrets des AppHost prüfen (dotnet user-secrets list --project src/OfficeSelfSigningPortal.AppHost) oder -AdminUser/-AdminPassword setzen (vgl. docs/development-setup.md).'
}

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
