namespace Ossp.Contracts;

/// <summary>
/// Queue-Namen der Message-Bus-Konvention (Anhang A: <c>ossp.&lt;message&gt;</c>).
/// </summary>
public static class QueueNames
{
    public const string ScanRequested = "ossp.scan-requested";
}

/// <summary>
/// Analyseauftrag WebUI → WorkerService (Anhang A, exakter Vertrag).
/// Der persistierte Analyseauftrag der Ingestion (T03) führt dieselben Felder —
/// <see cref="ContentSha256"/> ist die TOCTOU-Basis (TM-03/TM-19), der
/// SigningService verifiziert den Hash vor jeder Signatur.
/// </summary>
/// <param name="JobId">Vorgangs-ID, wird in allen Nachrichten geführt.</param>
/// <param name="ArtifactId">Referenz auf persistierten Datei-Blob (interner Speicher, kein Pfad nach außen).</param>
/// <param name="ContentSha256">Hex-SHA-256 des Blobs.</param>
/// <param name="OriginalFileName">Für AMSI contentName.</param>
/// <param name="ContentType">"xlsm" | "docm" | "pptm".</param>
/// <param name="FileSizeBytes">Größe des Blobs in Bytes.</param>
/// <param name="SubmittedBy">IdP-Objekt-ID (sub-Claim).</param>
/// <param name="RequestedAt">Zeitstempel (UTC).</param>
public sealed record ScanRequested(
    Guid JobId,
    Guid ArtifactId,
    string ContentSha256,
    string OriginalFileName,
    string ContentType,
    long FileSizeBytes,
    string SubmittedBy,
    DateTimeOffset RequestedAt);
