namespace OfficeSelfSigningPortal.WorkerService.Retention;

/// <summary>
/// Konfiguration des Retention-Jobs (Abschnitt <see cref="SectionName"/>, REQ-19):
/// Löschung von Original- und Signatur-Blobs nach der Signierung; Audit-Einträge
/// nach Ablauf der Aufbewahrungsfrist (append-only bis zur Grenze, REQ-19).
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

    /// <summary>
    /// Aufbewahrungsfrist der Audit-Einträge in Tagen ab Eintritt
    /// (Default 365 Tage = 1 Jahr, REQ-19, AK-19-Hintergrund). Nach Ablauf
    /// werden die ältesten Einträge in einem kontinuierlichen Block am
    /// Tabellenanfang gelöscht; die sanctioned Lösch-Grenze wird als
    /// <c>audit_chain_checkpoints</c>-Eintrag festgehalten, damit die
    /// Hash-Ketten-Prüfung beim Admin-Abruf weiterhin funktioniert
    /// (REQ-18, AK-07, AK-18). Die Fristgrenze läuft über dieselbe
    /// fälschbare Uhr wie <see cref="BlobRetentionDays"/>.
    /// </summary>
    public int AuditRetentionDays { get; set; } = 365;

    /// <summary>Ausführungsintervall des Jobs (Default: täglich).</summary>
    public TimeSpan ExecutionInterval { get; set; } = TimeSpan.FromDays(1);
}
