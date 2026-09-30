namespace OfficeSelfSigningPortal.WorkerService.Notifications;

/// <summary>
/// Adress-/Link-Konfiguration der Benachrichtigungen (Ticket 10): Die E-Mail
/// transportiert ausschließlich Status + Portal-Link (TM-02/TM-11) — der Link
/// braucht daher die öffentliche Portalbasis-URL.
/// </summary>
public sealed class NotificationOptions
{
    public const string SectionName = "Notifications";

    /// <summary>Öffentliche Basis-URL des Portals (ohne Slash am Ende) für den Vorgangslink.</summary>
    public string? PortalBaseUrl { get; set; }

    /// <summary>Empfänger der Security-Team-Benachrichtigung (Malicious-Pfad, REQ-13); null = deaktiviert.</summary>
    public string? SecurityTeamAddress { get; set; }
}
