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

    public PortalWebDbFactory(string connectionString) => _connectionString = connectionString;

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseSetting("Auth:UseTestAuthHandler", "true");
        builder.UseSetting("ConnectionStrings:portal", _connectionString);
        // MassTransit im InMemory-Transport fahren (kein Broker im Seam S1).
        builder.UseSetting("OsspBus:Transport", "InMemory");
    }
}

/// <summary>Gepinnte Testcontainers-Fabrik für das Tests-Projekt (vgl. IntegrationTests).</summary>
public static class TestContainers
{
    public static PostgreSqlContainer CreatePostgres() =>
        new PostgreSqlBuilder("postgres:17")
            .Build();
}
