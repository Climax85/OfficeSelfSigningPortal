namespace Ossp.AmsiScanBridge;

/// <summary>
/// Vertrags-Konstanten der AmsiScanBridge (F5, IF-10). Header- und Pfadnamen
/// sind bewusst englisch/kurz, damit der WorkerService-Client (C#) und ein
/// mögliches externes Test-/Probe-Skript dieselbe Sicht auf die Brücke haben.
/// </summary>
public static class AmsiScanBridgeEndpoints
{
    /// <summary>Pfad der Scan-Endpoint-Route.</summary>
    public const string ScanPath = "/scan";

    /// <summary>Pfad des token-freien Liveness/Readiness-Endpunkts.</summary>
    public const string HealthPath = "/health";

    /// <summary>Header für das Shared-Secret (Worker → Bridge).</summary>
    public const string TokenHeader = "X-Amsi-Bridge-Token";

    /// <summary>Header für den ursprünglichen Dateinamen (für AMSI contentName).</summary>
    public const string ContentNameHeader = "X-Content-Name";
}