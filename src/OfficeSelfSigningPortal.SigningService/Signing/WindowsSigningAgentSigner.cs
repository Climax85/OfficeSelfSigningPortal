using System.Security.Cryptography.X509Certificates;
using Ossp.Contracts;

namespace OfficeSelfSigningPortal.SigningService.Signing;

/// <summary>
/// Fallback hinter <see cref="IVbaProjectSigner"/> (ADR-0003): delegiert die Signierung an
/// einen Windows-Signier-Agenten (signtool + Office-SIPs, x86). Der Agent ist in der
/// Linux-Baseline (Anhang E) nicht verfügbar — der Fallback meldet einen stabilen
/// Fehlercode statt eine Signatur zu erfinden. Verdrahtung des Agenten ist eine
/// Betriebsentscheidung (Windows-Sidecar); die Selektion erfolgt per Konfiguration
/// (Options-Pattern, <c>Signing:Signer</c>).
/// </summary>
public sealed class WindowsSigningAgentSigner : IVbaProjectSigner
{
    public const string UnavailableErrorCode = "windows-signing-agent-unavailable";

    public Task<SignResult> SignAsync(Stream document, X509Certificate2 certificate, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        return Task.FromResult(new SignResult(false, UnavailableErrorCode));
    }
}
