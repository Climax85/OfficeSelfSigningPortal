namespace OfficeSelfSigningPortal.WebUI.LiveStatus;

/// <summary>Konfiguration des Live-Status-Kanals (REQ-20, IF-03).</summary>
public sealed class LiveStatusOptions
{
    public const string SectionName = "LiveStatus";

    /// <summary>
    /// Abfrageintervall des Status-Wächters auf den Saga-State-Store in Sekunden.
    /// Single-Replica v1 (REQ-20): Der Wächter läuft in der WebUI-Instanz und
    /// versorgt den SignalR-Hub — ein Backplane ist bewusst nicht vorgesehen.
    /// </summary>
    public int PollIntervalSeconds { get; set; } = 2;
}
