namespace OfficeSelfSigningPortal.WebUI.Data;

/// <summary>
/// Vorgangs-Status gemäß Saga-State-Machine (Anhang B). Die enum-Namen sind
/// die verbindlichen, deutschsprachigen Zustandsbezeichner (Serialisierung als String).
/// </summary>
public enum JobStatus
{
    Eingereicht,
    InValidierung,
    ScanLaeuft,
    ReviewAusstehend,
    RueckfrageAusstehend,
    SignierungAngefragt,
    Signiert,
    Abgelehnt,
    NichtSignierbar,
    Fehler,
}

/// <summary>
/// Persistierter Analyseauftrag (Vorgang) — führt die ScanRequested-Felder
/// (Anhang A) inkl. ContentSha256 als TOCTOU-Basis (TM-03).
/// Identifier folgen dem verbindlichen Nachrichtenvertrag (JobId/ArtifactId).
/// </summary>
public sealed class AnalysisJob
{
    public required Guid JobId { get; set; }
    public required Guid ArtifactId { get; set; }
    public required string SubmittedBy { get; set; }
    public required string OriginalFileName { get; set; }

    /// <summary>"xlsm" | "docm" | "pptm" (Vertrag Anhang A).</summary>
    public required string ContentType { get; set; }

    public required long FileSizeBytes { get; set; }
    public required string ContentSha256 { get; set; }
    public JobStatus Status { get; set; }
    public string? StatusReason { get; set; }
    public DateTimeOffset CreatedAt { get; set; }

    public Artifact Artifact { get; set; } = null!;
}

/// <summary>Persistierter Datei-Blob eines Vorgangs (interner Speicher, kein Pfad nach außen).</summary>
public sealed class Artifact
{
    public required Guid ArtifactId { get; set; }
    public required byte[] Content { get; set; }
    public required string ContentSha256 { get; set; }

    public AnalysisJob Job { get; set; } = null!;
}
