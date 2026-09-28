using Aspire.Hosting;
using Aspire.Hosting.Testing;
using Aspire.Hosting.ApplicationModel;

namespace OfficeSelfSigningPortal.Tests;

/// <summary>
/// Prüft das AppHost-Ressourcenmodell ohne Container-Start —
/// schneller Seam für die Skeleton-Verdrahtung (AK-27, AK-28).
/// </summary>
public class AppHostResourceTests
{
    private const string ParameterArgs =
        "--parameter:postgres-password=test" +
        ";--parameter:rabbitmq-user=test" +
        ";--parameter:rabbitmq-password=test" +
        ";--parameter:keycloak-admin=test" +
        ";--parameter:keycloak-admin-password=test";

    [Fact]
    public async Task AppHost_Enthaelt_alle_Infrastruktur_und_Projekt_Resourcen()
    {
        // Arrange
        var appBuilder = await DistributedApplicationTestingBuilder.CreateAsync<Projects.AppHost>(
            ParameterArgs.Split(';'));

        // Act
        var resourceNames = appBuilder.Resources.Select(r => r.Name).ToHashSet(StringComparer.OrdinalIgnoreCase);

        // Assert
        string[] expected =
        [
            "postgres",
            "portal",
            "worker",
            "signing",
            "rabbitmq",
            "keycloak",
            "mailpit",
            "webui",
            "workerservice",
            "signingservice"
        ];
        Assert.All(expected, name => Assert.Contains(name, resourceNames));
    }

    [Fact]
    public async Task AppHost_Orchestriert_genau_drei_Projekte()
    {
        // Arrange
        var appBuilder = await DistributedApplicationTestingBuilder.CreateAsync<Projects.AppHost>(
            ParameterArgs.Split(';'));

        // Act
        var projects = appBuilder.Resources.OfType<ProjectResource>().ToList();

        // Assert
        Assert.Equal(3, projects.Count);
        Assert.Contains(projects, p => p.Name == "webui");
        Assert.Contains(projects, p => p.Name == "workerservice");
        Assert.Contains(projects, p => p.Name == "signingservice");
    }

    [Fact]
    public async Task AppHost_Keycloak_und_MailPit_sind_Container_ohne_Dev_Credentials_im_Repo()
    {
        // Arrange
        var appBuilder = await DistributedApplicationTestingBuilder.CreateAsync<Projects.AppHost>(
            ParameterArgs.Split(';'));

        // Act
        var containers = appBuilder.Resources.OfType<ContainerResource>().ToList();

        // Assert
        Assert.Contains(containers, c => c.Name == "keycloak");
        Assert.Contains(containers, c => c.Name == "mailpit");
    }
}
