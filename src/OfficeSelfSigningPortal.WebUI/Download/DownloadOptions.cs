namespace OfficeSelfSigningPortal.WebUI.Download;

/// <summary>Konfiguration der Vorgangs-Downloads (AK-04, REQ-19).</summary>
public sealed class DownloadOptions
{
    public const string SectionName = "Downloads";

    /// <summary>
    /// Download-Fenster der signierten Datei in Tagen ab Eintritt von <c>Signiert</c>
    /// (Default 90, AK-04). Der Retention-Job (Ticket 11) löscht die Blobs zeitgleich —
    /// die Prüfung hier ist Verteidigung in der Tiefe (Verteiltes System, REQ-19).
    /// </summary>
    public int SignedDownloadRetentionDays { get; set; } = 90;
}
