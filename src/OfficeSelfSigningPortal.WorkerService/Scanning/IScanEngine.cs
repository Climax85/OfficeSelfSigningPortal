namespace OfficeSelfSigningPortal.WorkerService.Scanning;

/// <summary>Scan-Eingabe einer Engine-Stage: Dateiinhalt plus Vertrags-Metadaten aus ScanRequested (Anhang A).</summary>
/// <param name="Content">Datei-Bytes (Blob aus dem Artefakt-Speicher).</param>
/// <param name="OriginalFileName">Für AMSI contentName.</param>
/// <param name="ContentType">"xlsm" | "docm" | "pptm".</param>
public sealed record ScanTarget(
    byte[] Content,
    string OriginalFileName,
    string ContentType);

/// <summary>
/// Engine-Stage des Scan-Orchestrators (Seam S3, AK-47): injizierbar, austauschbar
/// gegen Fake-Engines im Unit-Seam und gegen Testcontainers-Engines im Integrations-Slice.
/// Eine Stage liefert Funde (State Ok) oder einen Betriebszustand — sie wirft keine
/// Exceptions in den Orchestrator (Ausfälle werden als EngineResult verdichtet).
/// </summary>
public interface IScanEngine
{
    /// <summary>"clamav" | "yara" | "amsi" (Anhang A).</summary>
    string EngineName { get; }

    Task<EngineRun> ScanAsync(ScanTarget target, CancellationToken cancellationToken);
}
