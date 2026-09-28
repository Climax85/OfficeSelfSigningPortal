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

/// <summary>Verbindliche Entscheidungswerte (Anhang A) — einzige Quelle für Saga und WebUI.</summary>
public static class ReviewDecisionValues
{
    public const string Freigeben = "Freigeben";
    public const string Ablehnen = "Ablehnen";
    public const string Rueckfrage = "Rueckfrage";
}
