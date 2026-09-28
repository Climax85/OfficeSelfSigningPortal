using Ossp.Contracts;

namespace OfficeSelfSigningPortal.WebUI.Review;

/// <summary>
/// Read-only Projektion eines Vorgangs aus dem persistierten Saga-State-Store
/// (<c>analysis_saga</c>, WorkerService-DB). Die Saga-Zeile ist der führende
/// Vorgangsstatus — die WebUI führt keinen eigenen Status (Upload-Zeile der
/// portal-DB bleibt Aufnahme-Evidenz).
/// </summary>
/// <param name="JobId">Vorgangs-ID (CorrelationId der Saga).</param>
/// <param name="CurrentState">Verbindlicher Zustandsname (Anhang B, <see cref="SagaStateNames"/>).</param>
/// <param name="SubmittedBy">IdP-Objekt-ID des Einreichers (sub-Claim).</param>
/// <param name="OriginalFileName">Basisname der eingereichten Datei.</param>
/// <param name="ContentType">"xlsm" | "docm" | "pptm" (Vertrag Anhang A).</param>
/// <param name="FileSizeBytes">Größe der Upload-Datei.</param>
/// <param name="ReceivedAt">Einreichzeit (Saga-Aufnahme, Basis der Alterungsanzeige).</param>
public sealed record SagaVorgangInfo(
    Guid JobId,
    string CurrentState,
    string SubmittedBy,
    string OriginalFileName,
    string ContentType,
    long FileSizeBytes,
    DateTimeOffset ReceivedAt);

/// <summary>
/// Lesezugriff der Review-API auf den Saga-State-Store. Implementierung ist
/// bewusst Npgsql-Raw-SQL (parametrisiert, CONVENTIONS §6) statt eines zweiten
/// EF-Kontexts über das fremde Schema — Vorbild: PostgresSagaStateReader des
/// SigningService (TM-19); die WebUI erhält keinen Schreibpfad auf die Saga.
/// </summary>
public interface ISagaReviewReader
{
    /// <summary>
    /// Offene Reviews (<c>ReviewAusstehend</c> und <c>RueckfrageAusstehend</c> —
    /// beide keine Endzustände, Anhang B) sortiert nach Einreichzeit aufsteigend
    /// (AK-06, TC-20).
    /// </summary>
    Task<IReadOnlyList<SagaVorgangInfo>> GetOpenReviewsAsync(CancellationToken cancellationToken);

    /// <summary>Einzelvorgang oder null, wenn die Saga keine Zeile dafür führt.</summary>
    Task<SagaVorgangInfo?> GetVorgangAsync(Guid jobId, CancellationToken cancellationToken);
}
