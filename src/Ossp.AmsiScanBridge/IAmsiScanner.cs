namespace Ossp.AmsiScanBridge;

/// <summary>
/// Eingabe für einen AMSI-Scan-Aufruf innerhalb der Bridge.
/// </summary>
/// <param name="Content">Datei-Bytes (kompletter Inhalt).</param>
/// <param name="ContentName">Dateiname (für AMSI contentName — Endpoint-AV-Signaturen
/// erwarten menschenlesbare Namen, nicht Hashes).</param>
/// <param name="ContentType">Inhaltstyp ("xlsm" | "docm" | "pptm" | leer).</param>
public sealed record AmsiScanCall(
    byte[] Content,
    string ContentName,
    string ContentType);

/// <summary>
/// AMSI-Scan-Ergebnis — verdichtet die native AMSI-Antwort.
/// </summary>
/// <param name="IsMalicious"><c>true</c> bei AMSI-Detection, sonst <c>false</c>.</param>
/// <param name="Name">Detections-Name (z. B. <c>Win.Test.Signature</c>), nur bei <see cref="IsMalicious"/>.</param>
public sealed record AmsiDetection(bool IsMalicious, string? Name)
{
    public static AmsiDetection Clean { get; } = new(IsMalicious: false, Name: null);
}

/// <summary>
/// Plattformabhängige AMSI-Scan-Senke. Der Produktionspfad
/// (<see cref="WindowsAmsiScanner"/>) ruft die Windows-AMSI-APIs auf; auf
/// Nicht-Windows-Plattformen liefert <see cref="NonWindowsAmsiScanner"/> ein
/// dokumentiertes Clean-Ergebnis, damit Bridge-Code kompilier- und startbar
/// bleibt (Tests, Linux-CI). Die Inconclusive-Policy im WorkerService
/// (TC-19, AK-26) macht einen Ausfall am Produktivpfad zum Review-Pflicht-Fall;
/// eine grundsätzlich leere Brücke auf einem Windows-Host fällt damit genauso
/// auf wie ein Timeout (TM-15, REQ-12).
/// </summary>
public interface IAmsiScanner
{
    Task<AmsiDetection> ScanAsync(AmsiScanCall call, CancellationToken cancellationToken);
}