namespace OfficeSelfSigningPortal.WebUI.Review;

/// <summary>
/// Konfiguration der Review-API (Options-Pattern, CONVENTIONS §2): Eingabelimits
/// (CONVENTIONS §6 — externe Eingaben als untrusted) und Rate-Limit des
/// Rückfrage-Kanals (TM-02).
/// </summary>
public sealed class ReviewOptions
{
    public const string SectionName = "Review";

    /// <summary>Maximale Länge eines Review-Kommentars/Begründung (Zeichen).</summary>
    public int MaxCommentLength { get; set; } = 2000;

    /// <summary>Maximale Länge einer Rückfrage-Antwort (Zeichen).</summary>
    public int MaxAnswerLength { get; set; } = 4000;

    /// <summary>Anzahl erlaubter Rückfrage-Antworten pro Fenster und Nutzer (TM-02).</summary>
    public int RueckfrageRateLimitPermitLimit { get; set; } = 10;

    /// <summary>Fensterlänge des Rückfrage-Rate-Limits in Sekunden (TM-02).</summary>
    public int RueckfrageRateLimitWindowSeconds { get; set; } = 60;
}
