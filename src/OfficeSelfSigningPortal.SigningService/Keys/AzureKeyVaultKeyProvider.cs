using Ossp.Contracts;

namespace OfficeSelfSigningPortal.SigningService.Keys;

/// <summary>
/// Fallback-Key-Provider über Azure Key Vault (AK-53): Nicht-Betriebs-VBA-Signing erfordert
/// einen exportierbaren Key (Research R2, AzureSignTool#126) — die Verdrahtung ist bewusst
/// ein Betriebs-Backlog. Konfiguriert sich der Provider, schlägt der Start kontrolliert
/// fehl (fail-fast statt stillschweigendem Fallback auf keinen Provider).
/// </summary>
public sealed class AzureKeyVaultKeyProvider : ICodeSigningKeyProvider
{
    public const string NotImplementedError =
        "AzureKeyVaultKeyProvider ist nicht implementiert — Betriebs-Backlog (exportierbarer Key erforderlich, Research R2).";

    public Task<System.Security.Cryptography.X509Certificates.X509Certificate2> GetSigningCertificateAsync(
        CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        throw new NotSupportedException(NotImplementedError);
    }
}
