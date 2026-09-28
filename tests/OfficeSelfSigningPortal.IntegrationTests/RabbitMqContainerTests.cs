using System.Net.Sockets;
using OfficeSelfSigningPortal.IntegrationTests.Testcontainers;

namespace OfficeSelfSigningPortal.IntegrationTests;

[Trait("Category", "Integration")]
public class RabbitMqContainerTests
{
    [Fact]
    public async Task RabbitMqContainer_Startet_und_erreichbar_Amqp_Port()
    {
        // Arrange
        await using var container = TestContainers.CreateRabbitMq();
        await container.StartAsync();

        // Act
        using var client = new TcpClient();
        await client.ConnectAsync("localhost", container.GetMappedPublicPort(5672));

        // Assert
        Assert.True(client.Connected);
    }
}
