using Microsoft.Extensions.Logging;

namespace Ossp.AmsiScanBridge;

/// <summary>
/// Fallback-AMSI-Scanner auf Nicht-Windows-Plattformen (F5, ADR-0004). Liefert
/// verbindlich <see cref="AmsiDetection.Clean"/> zurück und protokolliert die
/// Limitation: AMSI ist eine Windows-API; auf Linux/macOS liefert die Bridge
/// einen Clean-Verdict — Endpoint-AV-Schutz ist auf Nicht-Windows-Hosts nicht
/// verfügbar.
///
/// <para>Im Aspire-Dev-Betrieb ist die Bridge zwar lauffähig (Smoke-Check für
/// Profil <c>hardened</c>, AK-57), aber für echte AMSI-Ergebnisse muss sie
/// auf einem Windows-Host deployt werden — siehe §14.6 OP-10b in der
/// Anwendungsdokumentation und ADR-0004.</para>
/// </summary>
public sealed class NonWindowsAmsiScanner(ILogger<NonWindowsAmsiScanner> logger) : IAmsiScanner
{
    public Task<AmsiDetection> ScanAsync(AmsiScanCall call, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(call);
        cancellationToken.ThrowIfCancellationRequested();

        logger.LogInformation(
            "AMSI-Bridge auf Nicht-Windows-Host: Clean-Ergebnis ohne Endpoint-AV-Pruefung (ContentName={ContentName}).",
            call.ContentName);
        return Task.FromResult(AmsiDetection.Clean);
    }
}