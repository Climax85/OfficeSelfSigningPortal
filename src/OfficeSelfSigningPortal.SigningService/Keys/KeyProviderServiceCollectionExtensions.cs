using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Ossp.Contracts;

namespace OfficeSelfSigningPortal.SigningService.Keys;

/// <summary>
/// Konfiguration der Key-Provider-Auswahl (Options-Pattern, CONVENTIONS §2).
/// </summary>
public sealed class KeyProviderOptions
{
    public const string SectionName = "Signing:KeyProvider";

    /// <summary>LocalDev | CyberArkConjur | AzureKeyVault (Anhang E, AK-53).</summary>
    public string Provider { get; set; } = "LocalDev";
}

/// <summary>
/// Registrierung der Key-Provider mit Start-Zwangspüfung (AK-54, TC-35, TM-20):
/// Der LocalDevKeyProvider ist außerhalb des Dev-Profils (<c>Deployment:Profile=dev</c>)
/// unzulässig — der Start wird mit eindeutiger Fehlermeldung verweigert (fail-fast).
/// </summary>
public static class KeyProviderServiceCollectionExtensions
{
    public const string DevProfileName = "dev";

    public static IServiceCollection AddCodeSigningKeyProvider(
        this IServiceCollection services, IConfiguration configuration)
    {
        var options = configuration.GetSection(KeyProviderOptions.SectionName).Get<KeyProviderOptions>()
            ?? new KeyProviderOptions();
        var profile = configuration["Deployment:Profile"] ?? "baseline";

        switch (options.Provider)
        {
            case "LocalDev":
                if (!string.Equals(profile, DevProfileName, StringComparison.OrdinalIgnoreCase))
                {
                    throw new InvalidOperationException(
                        $"LocalDevKeyProvider ist außerhalb des Dev-Profils nicht zulässig " +
                        $"(Deployment:Profile='{profile}'). Konfigurieren Sie Signing:KeyProvider:Provider=CyberArkConjur " +
                        $"(AK-54, TC-35, REQ-15/24).");
                }

                services.AddSingleton<ICodeSigningKeyProvider, LocalDevKeyProvider>();
                break;

            case "CyberArkConjur":
                services.AddSingleton<ICodeSigningKeyProvider>(provider =>
                {
                    var conjurOptions = configuration
                        .GetSection(ConjurKeyProviderOptions.SectionName)
                        .Get<ConjurKeyProviderOptions>()
                        ?? throw new InvalidOperationException(
                            $"Abschnitt '{ConjurKeyProviderOptions.SectionName}' fehlt — " +
                            "CyberArk-Conjur-Verbindung muss konfiguriert sein (AK-55, REQ-15).");
                    var handler = new SocketsHttpHandler();
                    return new CyberArkConjurKeyProvider(new HttpClient(handler), conjurOptions);
                });
                break;

            case "AzureKeyVault":
                services.AddSingleton<ICodeSigningKeyProvider, AzureKeyVaultKeyProvider>();
                break;

            default:
                throw new InvalidOperationException(
                    $"Unbekannter Signing:KeyProvider:Provider '{options.Provider}' " +
                    "(gültig: LocalDev | CyberArkConjur | AzureKeyVault).");
        }

        return services;
    }
}
