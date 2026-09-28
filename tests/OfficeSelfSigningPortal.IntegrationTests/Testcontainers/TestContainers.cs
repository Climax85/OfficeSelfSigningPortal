using Testcontainers.PostgreSql;
using Testcontainers.RabbitMq;

namespace OfficeSelfSigningPortal.IntegrationTests.Testcontainers;

/// <summary>
/// Zentrale Fabriken für Testcontainers-Instanzen. Versionen sind gepinnt,
/// damit CI und lokale Runs identische Images verwenden.
/// </summary>
public static class TestContainers
{
    public static PostgreSqlContainer CreatePostgres() =>
        new PostgreSqlBuilder("postgres:17")
            .Build();

    public static RabbitMqContainer CreateRabbitMq() =>
        new RabbitMqBuilder("rabbitmq:4-alpine")
            // Eigener User (statt guest): RabbitMQ erlaubt guest nur von Loopback-Peers —
            // über Docker-NAT wäre die Verbindung sonst abgelehnt.
            .WithUsername("ossp")
            .WithPassword("ossp-test")
            .Build();
}
