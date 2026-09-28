using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using OfficeSelfSigningPortal.WebUI.Components;

namespace OfficeSelfSigningPortal.Tests.Support;

/// <summary>
/// Seam S1 (AK-34): startet die WebUI mit dem Test-AuthHandler als Fake-IdP.
/// Aktiviert denselben Konfigurationsschalter wie die produktive Verdrahtung,
/// ersetzt aber keinen Produktivcode. <see cref="App"/> dient nur als
/// Assembly-Marker für die WebUI (beide Assemblys haben einen globalen
/// <c>Program</c>-Typ).
/// </summary>
public sealed class PortalWebFactory : WebApplicationFactory<App>
{
    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseSetting("Auth:UseTestAuthHandler", "true");
        // MassTransit im InMemory-Transport fahren (kein Broker im Seam S1);
        // Outbox-Tabellen liegen auf dem Test-PostgreSQL der S1-Fixtures.
        builder.UseSetting("OsspBus:Transport", "InMemory");
        // Nur-AuthZ-Probes greifen nie auf die Datenbank zu (kein Kontainer im
        // Fixture) — Dummy-Connection-String, die harte Startprüfung greift trotzdem.
        builder.UseSetting("ConnectionStrings:portal", "Host=unused.invalid;Database=probe-only;Username=probe;Password=probe");
    }
}
