using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using OfficeSelfSigningPortal.WebUI.Components;
using Testcontainers.PostgreSql;

namespace OfficeSelfSigningPortal.Tests.Support;

/// <summary>
/// Seam S1 mit Persistenz: startet die WebUI mit Test-AuthHandler und einem
/// Testcontainers-PostgreSQL als 'portal'-Datenbank (Trait "Integration").
/// </summary>
public sealed class PortalWebDbFactory : WebApplicationFactory<App>
{
    private readonly string _connectionString;
    private readonly string? _sagaStateConnectionString;
    private readonly IReadOnlyDictionary<string, string>? _extraSettings;

    /// <param name="connectionString">Connection String der portal-DB (Testcontainers).</param>
    /// <param name="sagaStateConnectionString">
    /// Read-only-Saga-State-Store (analysis_saga). null = Dummy (Endpunkte, die den
    /// Reader aufrufen, werden von diesen Fixtures nicht getestet).
    /// </param>
    /// <param name="extraSettings">Zusätzliche Konfigurationswerte (z. B. LiveStatus-Pollintervall).</param>
    public PortalWebDbFactory(
        string connectionString,
        string? sagaStateConnectionString = null,
        IReadOnlyDictionary<string, string>? extraSettings = null)
    {
        _connectionString = connectionString;
        _sagaStateConnectionString = sagaStateConnectionString;
        _extraSettings = extraSettings;
    }

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseSetting("Auth:UseTestAuthHandler", "true");
        builder.UseSetting("ConnectionStrings:portal", _connectionString);
        // MassTransit im InMemory-Transport fahren (kein Broker im Seam S1).
        builder.UseSetting("OsspBus:Transport", "InMemory");
        // Siehe PortalWebFactory: Dummy-Connection-String, harte Startprüfung greift trotzdem.
        builder.UseSetting(
            "ConnectionStrings:sagastate",
            _sagaStateConnectionString ?? "Host=unused.invalid;Database=saga-probe-only;Username=probe;Password=probe");
        if (_extraSettings is not null)
        {
            foreach (var (key, value) in _extraSettings)
            {
                builder.UseSetting(key, value);
            }
        }
    }
}

/// <summary>Gepinnte Testcontainers-Fabrik für das Tests-Projekt (vgl. IntegrationTests).</summary>
public static class TestContainers
{
    public static PostgreSqlContainer CreatePostgres() =>
        new PostgreSqlBuilder("postgres:17")
            .Build();
}
