using OfficeSelfSigningPortal.WebUI.Review;

namespace OfficeSelfSigningPortal.WebUI.LiveStatus;

/// <summary>Push-Ereignis: Zustandsänderung eines beobachteten Vorgangs (AK-02, IF-03).</summary>
/// <param name="JobId">Vorgangs-ID.</param>
/// <param name="Status">Verbindlicher Zustandsname (Anhang B).</param>
/// <param name="SignedArtifactId">Referenz auf den signierten Blob, sobald vorhanden (Download-Freigabe in der UI).</param>
/// <param name="ChangedAt">Beobachtungszeitpunkt der Änderung (UTC).</param>
public sealed record JobStatusChangedEvent(
    Guid JobId,
    string Status,
    Guid? SignedArtifactId,
    DateTimeOffset ChangedAt);

/// <summary>Push-Ereignis: Aktualisierung der offenen Reviews fürs Bearbeiter-Dashboard (AK-06).</summary>
public sealed record OpenReviewsChangedEvent(IReadOnlyList<OpenReviewItem> Reviews);

/// <summary>Push-Ereignis: In-Portal-Benachrichtigung an den Einreicher (AK-08, REQ-08).</summary>
/// <param name="JobId">Vorgangs-ID.</param>
/// <param name="OriginalFileName">Basisname der eingereichten Datei.</param>
/// <param name="State">Erreichten Zustand (Endzustand oder Rückfrage, Anhang B).</param>
/// <param name="OccurredAt">Eintrittszeitpunkt (UTC).</param>
public sealed record VorgangNotificationEvent(
    Guid JobId,
    string OriginalFileName,
    string State,
    DateTimeOffset OccurredAt);
