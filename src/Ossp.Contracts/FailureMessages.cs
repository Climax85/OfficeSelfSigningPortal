namespace Ossp.Contracts;

/// <summary>
/// Fehlerpfad (alle Services, Anhang A). Stage-basierte Behandlung in der Saga:
/// "ingestion" → <c>Abgelehnt</c> (in InValidierung), "scan"/"signing" → <c>Fehler</c>.
/// Stage "review" ist ein reines Meldungs-/Audit-Event (SoD-Verletzung) — die Saga
/// behandelt es nicht, um Selbst-Loops zu vermeiden (Freigabe bleibt einem zweiten
/// Bearbeiter vorbehalten, TC-22).
/// </summary>
/// <param name="JobId">Vorgangs-ID.</param>
/// <param name="Stage">"ingestion" | "scan" | "review" | "signing" | "notification".</param>
/// <param name="Reason">fachlicher Grund (keine Exception-Texte).</param>
/// <param name="Retryable">false ⇒ kein erneuter Versuch.</param>
/// <param name="FailedAt">Zeitstempel (UTC).</param>
public sealed record JobFailed(
    Guid JobId,
    string Stage,
    string Reason,
    bool Retryable,
    DateTimeOffset FailedAt);
