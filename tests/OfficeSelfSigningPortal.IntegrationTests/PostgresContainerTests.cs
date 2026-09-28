using Npgsql;
using OfficeSelfSigningPortal.IntegrationTests.Testcontainers;

namespace OfficeSelfSigningPortal.IntegrationTests;

[Trait("Category", "Integration")]
public class PostgresContainerTests
{
    [Fact]
    public async Task PostgresContainer_Startet_und_akzeptiert_Verbindungen()
    {
        // Arrange
        await using var container = TestContainers.CreatePostgres();
        await container.StartAsync();

        // Act
        await using var connection = new NpgsqlConnection(container.GetConnectionString());
        await connection.OpenAsync();
        await using var command = new NpgsqlCommand("SELECT 1", connection);
        var result = await command.ExecuteScalarAsync();

        // Assert
        Assert.Equal(1, result);
    }
}
