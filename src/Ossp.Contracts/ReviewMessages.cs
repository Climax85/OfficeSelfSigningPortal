namespace Ossp.Contracts;

/// <summary>
/// Review-Entscheidung WebUI → Saga + Audit (Anhang A, exakter Vertrag).
/// Die SoD-Prüfung (ReviewerId ≠ SubmitterId für Freigaben, REQ-17/TM-18)
/// erfolgt in der Saga; die WebUI erzwingt zusätzlich AuthZ (REQ-09, TM-17).
/// </summary>
/// <param name="JobId">Vorgangs-ID.</param>
/// <param name="ReviewerId">IdP-Objekt-ID des Bearbeiters.</param>
/// <param name="Decision">"Freigeben" | "Ablehnen" | "Rueckfrage".</param>
/// <param name="Comment">optionaler Kommentar (XSS-gefiltert in Ticket 07).</param>
/// <param name="DecidedAt">Zeitstempel (UTC).</param>
public sealed record ReviewDecisionRecorded(
    Guid JobId,
    string ReviewerId,
    string Decision,
    string? Comment,
    DateTimeOffset DecidedAt);

/// <summary>
/// RueckfrageAusstehend → ReviewAusstehend ("Einreicher-Antwort eingegangen", Anhang B).
/// Begründete Abweichung von Anhang A (exakte Contract-Liste): Die Antwort quert seit
/// Ticket 07 die Service-Grenze WebUI → Saga und ist damit eine Vertragsnachricht
/// (vorher WorkerService-intern, siehe InternalSagaEvents.cs). Shape unverändert.
/// Die WebUI staged sie über die EF-Core-Outbox (REQ-11, TM-06) und filtert aktive
/// Inhalte vor der Publikation (AK-49, TC-26).
/// </summary>
/// <param name="JobId">Vorgangs-ID.</param>
/// <param name="Antwort">XSS-gefilterte Antwort des Einreichers (Plaintext, escaped).</param>
/// <param name="SubmittedBy">IdP-Objekt-ID des Einreichers (sub-Claim).</param>
/// <param name="BeantwortetAm">Zeitstempel (UTC).</param>
public sealed record EinreicherAntwortEingegangen(
    Guid JobId,
    string Antwort,
    string SubmittedBy,
    DateTimeOffset BeantwortetAm);

/// <summary>Verbindliche Entscheidungswerte (Anhang A) — einzige Quelle für Saga und WebUI.</summary>
public static class ReviewDecisionValues
{
    public const string Freigeben = "Freigeben";
    public const string Ablehnen = "Ablehnen";
    public const string Rueckfrage = "Rueckfrage";
}
