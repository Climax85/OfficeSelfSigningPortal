namespace OfficeSelfSigningPortal.WebUI.Notifications;

/// <summary>Konfiguration der In-Portal-Benachrichtigungen (AK-08, REQ-08).</summary>
public sealed class NotificationOptions
{
    public const string SectionName = "Notifications";

    /// <summary>Maximale Einträge der Benachrichtigungsliste (neueste zuerst).</summary>
    public int Limit { get; set; } = 50;
}
