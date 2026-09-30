namespace OfficeSelfSigningPortal.WorkerService.Retention;

/// <summary>
/// Konfiguration des Retention-Jobs (Abschnitt <see cref="SectionName"/>, REQ-19):
/// Löschung von Original- und Signatur-Blobs nach der Signierung; Scan-Ergebnisse
/// und Audit-Metadaten bleiben append-only bestehen (kein Löschpfad).
/// </summary>
public sealed class RetentionOptions
{
    public const string SectionName = "Retention";

    /// <summary>
    /// Aufbewahrungsfrist der Blobs (Original + signiert) in Tagen ab Signierung
    /// (Default 90, REQ-19/AK-19). Deckt sich mit dem Download-Fenster der WebUI
    /// (<c>Downloads:SignedDownloadRetentionDays</c>) — beide sind Verteidigung
    /// in der Tiefe füreinander.
    /// </summary>
    public int BlobRetentionDays { get; set; } = 90;

    /// <summary>Ausführungsintervall des Jobs (Default: täglich).</summary>
    public TimeSpan ExecutionInterval { get; set; } = TimeSpan.FromDays(1);
}
