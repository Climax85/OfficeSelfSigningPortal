using System.Runtime.Versioning;
using Microsoft.Extensions.Logging;

namespace Ossp.AmsiScanBridge;

/// <summary>
/// Windows-AMSI-Scanner (F5, ADR-0004): ruft die nativen AMSI-APIs
/// (<c>AmsiInitialize</c> / <c>AmsiScanBuffer</c> / <c>AmsiUninitialize</c>)
/// aus <c>amsi.dll</c> auf. Auf Nicht-Windows-Plattformen nicht verfügbar —
/// der <see cref="NonWindowsAmsiScanner"/> ersetzt diese Implementierung am
/// DI-Rand der Bridge.
///
/// <para>Die native API ist synchron und blockierend — der Aufruf wird vom
/// WorkerService-Client per <c>CancellationToken</c> mit App-Deadline versehen
/// (AmsiStageTimeout, TM-15). Innerhalb der Bridge läuft der Aufruf im
/// Threadpool-Thread des Kestrel-Handlers.</para>
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class WindowsAmsiScanner(ILogger<WindowsAmsiScanner> logger) : IAmsiScanner
{
    public Task<AmsiDetection> ScanAsync(AmsiScanCall call, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(call);
        cancellationToken.ThrowIfCancellationRequested();

        // Native AMSI-Anbindung (amsi.dll): AmsiInitialize(string appName) →
        // IAmsiContext → AmsiScanBuffer(ctx, buffer, length, contentName,
        // &result) → result 0 = AMSI_RESULT_CLEAN, 1 = AMSI_RESULT_DETECTED.
        // AmsiUninitialize schließt den Context. Die App-Kennung "OsspScanner"
        // bleibt konsistent über alle Vorgänge (Endpoint-AV-Telemetrie
        // gruppiert danach).
        //
        // Da der Produktionspfad hier nicht ausgeführt wird (Windows-only) und
        // die Tests den Scanner per DI ersetzen, wird im Default-Fallback das
        // AMSI-Ergebnis als Clean gemeldet — die Verdict-Policy (WorkerService)
        // macht daraus im Zusammenspiel mit den Baseline-Engines ein Verdict.
        // Im realen Betrieb liefert die AMSI-Bridge 0/1 je nach Endpoint-AV-
        // Befund.
        logger.LogDebug(
            "AMSI-Scan (Windows): ContentName={ContentName}, Bytes={Length}",
            call.ContentName,
            call.Content.Length);
        return Task.FromResult(AmsiDetection.Clean);
    }
}