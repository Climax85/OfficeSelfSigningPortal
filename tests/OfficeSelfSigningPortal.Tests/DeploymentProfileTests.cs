using Aspire.Hosting;
using Aspire.Hosting.ApplicationModel;
using Aspire.Hosting.Testing;

namespace OfficeSelfSigningPortal.Tests;

/// <summary>
/// Seam für Ticket 12 (AK-57, Anhang E): Die Deployment-Profile <c>baseline</c> und
/// <c>hardened</c> sind im AppHost wählbar; <c>hardened</c> aktiviert die AMSI-Bridge-Stage
/// (REQ-12) — geprüft am Ressourcenmodell ohne Container-Start.
/// </summary>
public class DeploymentProfileTests
{
    private const string ParameterArgs =
        "--parameter:postgres-password=test" +
        ";--parameter:rabbitmq-user=test" +
        ";--parameter:rabbitmq-password=test" +
        ";--parameter:keycloak-admin=test" +
        ";--parameter:keycloak-admin-password=test";

    private const string HardenedArgs = ParameterArgs +
        ";--Deployment:Profile=hardened" +
        ";--parameter:amsi-bridge-token=test-shared-secret";

    [Fact]
    public async Task AppHost_Baseline_als_Default_aktiviert_die_AMSI_Stage_nicht()
    {
        // Arrange
        var appBuilder = await DistributedApplicationTestingBuilder.CreateAsync<Projects.AppHost>(
            ParameterArgs.Split(';'));

        // Act
        var environment = await ResolveEnvironmentAsync(appBuilder, "workerservice");

        // Assert — Anhang E: Profil baseline meldet AMSI verbindlich als Absent
        // (keine Stage registriert, AK-46); der AppHost setzt keinen AMSI-Schalter.
        Assert.DoesNotContain(environment,
            kv => kv.Key == "Scanning__Engines__AmsiEnabled" && string.Equals(kv.Value?.ToString(), "true", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task AppHost_Baseline_registriert_die_AMSI_Bridge_nicht()
    {
        // Arrange (F5, Anhang E): nur das Profil hardened startet die Bridge.
        var appBuilder = await DistributedApplicationTestingBuilder.CreateAsync<Projects.AppHost>(
            ParameterArgs.Split(';'));

        // Act
        var hasBridge = appBuilder.Resources.Any(r => r.Name == "amsiscanbridge");

        // Assert
        Assert.False(hasBridge, "AppHost-Profil baseline startet die AmsiScanBridge nicht.");
    }

    [Fact]
    public async Task AppHost_Hardened_aktiviert_die_AMSI_Bridge_Stage()
    {
        // Arrange
        var appBuilder = await DistributedApplicationTestingBuilder.CreateAsync<Projects.AppHost>(
            HardenedArgs.Split(';'));

        // Act
        var environment = await ResolveEnvironmentAsync(appBuilder, "workerservice");

        // Assert — Anhang E/AK-57: hardened registriert die AMSI-Stage am WorkerService
        // und verdrahtet die betriebsseitig bereitgestellte Bridge-URL.
        var amsiEnabled = Assert.Single(environment, kv => kv.Key == "Scanning__Engines__AmsiEnabled");
        Assert.Equal("true", amsiEnabled.Value?.ToString(), ignoreCase: true);

        var bridgeUrl = Assert.Single(environment, kv => kv.Key == "Scanning__Engines__AmsiBridgeUrl");
        var parameter = Assert.IsType<ParameterResource>(bridgeUrl.Value);
        Assert.Equal("amsi-bridge-url", parameter.Name);
    }

    [Fact]
    public async Task AppHost_Hardened_verdrahtet_den_BridgeToken_an_Worker_und_Bridge()
    {
        // Arrange (F5, SF-04): der amsi-bridge-token-Parameter wird sowohl in den
        // WorkerService (Scanning__Engines__AmsiBridgeToken) als auch in die
        // AmsiScanBridge (AmsiScanBridge__Token) eingespielt — ohne diese
        // Verdrahtung antwortet die Brücke 401 und die Inconclusive-Policy
        // (TC-19, AK-26) löst jeden Vorgang in Review-Pflicht auf.
        var appBuilder = await DistributedApplicationTestingBuilder.CreateAsync<Projects.AppHost>(
            HardenedArgs.Split(';'));

        // Act
        var workerEnvironment = await ResolveEnvironmentAsync(appBuilder, "workerservice");
        var bridgeEnvironment = await ResolveEnvironmentAsync(appBuilder, "amsiscanbridge");

        // Assert
        var workerToken = Assert.Single(workerEnvironment, kv => kv.Key == "Scanning__Engines__AmsiBridgeToken");
        var workerTokenParameter = Assert.IsType<ParameterResource>(workerToken.Value);
        Assert.Equal("amsi-bridge-token", workerTokenParameter.Name);

        var bridgeToken = Assert.Single(bridgeEnvironment, kv => kv.Key == "AmsiScanBridge__Token");
        var bridgeTokenParameter = Assert.IsType<ParameterResource>(bridgeToken.Value);
        Assert.Equal("amsi-bridge-token", bridgeTokenParameter.Name);
    }

    [Fact]
    public async Task AppHost_Hardened_registriert_die_AMSI_Bridge_als_Ressource()
    {
        // Arrange (F5, Anhang E): die Brücke ist ein eigenes Projekt und wird im
        // Profil hardened als eigene AppHost-Ressource gestartet — sonst fehlt
        // der Smoke-Check-Pfad (AK-57) und die AMSI-Stage kann im Dev-Profil
        // nicht wirklich getestet werden.
        var appBuilder = await DistributedApplicationTestingBuilder.CreateAsync<Projects.AppHost>(
            HardenedArgs.Split(';'));

        // Act
        var hasBridge = appBuilder.Resources.Any(r => r.Name == "amsiscanbridge");

        // Assert
        Assert.True(hasBridge, "AppHost-Profil hardened startet die AmsiScanBridge als Ressource (AK-57).");
    }

    [Fact]
    public async Task AppHost_Unbekanntes_Profil_verweigert_den_Start()
    {
        // Arrange — fail-fast statt stillschweigendem Fallback (CONVENTIONS: Validierung am Systemrand).
        var args = (ParameterArgs + ";--Deployment:Profile=invalid").Split(';');

        // Act
        var exception = await Record.ExceptionAsync(
            () => DistributedApplicationTestingBuilder.CreateAsync<Projects.AppHost>(args));

        // Assert
        Assert.NotNull(exception);
        Assert.Contains("invalid", exception.ToString(), StringComparison.Ordinal);
        Assert.Contains("baseline | hardened", exception.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task AppHost_Hardened_laesst_den_Dev_KeyProvider_des_SigningService_unveraendert()
    {
        // Arrange — Das Anhang-E-Profil steuert Engine-Stages/Härtung, nicht das
        // Schlüsselmanagement: Der AppHost bleibt Dev-Umgebung (AK-54, LocalDev nur hier).
        var appBuilder = await DistributedApplicationTestingBuilder.CreateAsync<Projects.AppHost>(
            HardenedArgs.Split(';'));

        // Act
        var environment = await ResolveEnvironmentAsync(appBuilder, "signingservice");

        // Assert
        var profile = Assert.Single(environment, kv => kv.Key == "Deployment__Profile");
        Assert.Equal("dev", profile.Value?.ToString(), ignoreCase: true);
    }

    private static async Task<IReadOnlyDictionary<string, object?>> ResolveEnvironmentAsync(
        IDistributedApplicationTestingBuilder appBuilder, string projectName)
    {
        var project = appBuilder.Resources.OfType<ProjectResource>().Single(p => p.Name == projectName);
        var context = new EnvironmentCallbackContext(
            new DistributedApplicationExecutionContext(DistributedApplicationOperation.Run),
            project);
        foreach (var annotation in project.Annotations.OfType<EnvironmentCallbackAnnotation>())
        {
            await annotation.Callback(context);
        }

        return context.EnvironmentVariables;
    }
}
