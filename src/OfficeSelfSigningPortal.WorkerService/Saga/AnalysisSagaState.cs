using MassTransit;
using Ossp.Contracts;

namespace OfficeSelfSigningPortal.WorkerService.Saga;

/// <summary>
/// Persistierter Zustand der <see cref="AnalysisSaga"/> (MassTransit State Machine Saga,
/// Anhang B). Die Zeile ist zugleich der führende Vorgangsstatus — Endzustände bleiben
/// als Zeile bestehen (kein Abschluss-Löschen), damit Vorgänge abfragbar bleiben (REQ-11).
/// </summary>
public sealed class AnalysisSagaState : SagaStateMachineInstance
{
    public Guid CorrelationId { get; set; }

    /// <summary>Aktueller Zustandsname (Anhang B, Werte aus <see cref="SagaStateNames"/>).</summary>
    public string CurrentState { get; set; } = string.Empty;

    // Vorgangskontext aus ScanRequested (Anhang A) — SoD-Prüfung (REQ-17) und
    // Signierauftrag (TM-19/REQ-14) brauchen dieselben Felder.
    public string SubmittedBy { get; set; } = string.Empty;

    /// <summary>
    /// E-Mail-Adresse des Einreichers (E-Mail-Claim des IdP, Anhang-A-Feld seit
    /// Ticket 10); null, wenn der IdP keinen liefert. Zustellbasis der E-Mail-
    /// Benachrichtigung (REQ-08).
    /// </summary>
    public string? SubmitterEmail { get; set; }
    public Guid ArtifactId { get; set; }
    public string ContentSha256 { get; set; } = string.Empty;
    public string OriginalFileName { get; set; } = string.Empty;
    public string ContentType { get; set; } = string.Empty;
    public long FileSizeBytes { get; set; }
    public DateTimeOffset ReceivedAt { get; set; }

    /// <summary>
    /// Referenz auf den signierten Blob (neue Artefakt-Zeile, Ticket 08) — dauerhafte
    /// Vorgang → Signatur-Zuordnung für Download (TC-27/AK-04, T09) und Retention (T11).
    /// </summary>
    public Guid? SignedArtifactId { get; set; }
}
