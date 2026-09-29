using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.SignalR;
using OfficeSelfSigningPortal.WebUI.Authentication;
using OfficeSelfSigningPortal.WebUI.Review;
using Ossp.Contracts;

namespace OfficeSelfSigningPortal.WebUI.LiveStatus;

/// <summary>
/// SignalR-Hub für Live-Status, Dashboard und In-Portal-Benachrichtigungen
/// (IF-03, AK-02/AK-06/AK-08/AK-20). Authentifizierung zwingend (FallbackPolicy);
/// Autorisierung je Beobachtung serverseitig in den Watch-Methoden (TM-17) —
/// keine rollenbezogenen Entscheidungen clientseitig.
/// </summary>
[Authorize]
public sealed class JobStatusHub(
    ISagaReviewReader reader,
    StatusWatchTracker tracker) : Hub
{
    /// <summary>Hub-Route (IF-03).</summary>
    public const string Route = "/hubs/jobstatus";

    /// <summary>Client-Methode für Zustandsänderungen eines Vorgangs.</summary>
    public const string JobStatusChangedMethod = "JobStatusChanged";

    /// <summary>Client-Methode für Dashboard-Aktualisierungen.</summary>
    public const string OpenReviewsChangedMethod = "OpenReviewsChanged";

    /// <summary>Client-Methode für In-Portal-Benachrichtigungen.</summary>
    public const string VorgangNotificationMethod = "VorgangNotification";

    /// <summary>Server-Methoden der Watch-Verdrahtung (Invoke-Seite der Komponenten).</summary>
    public const string WatchJobMethodName = "WatchJob";
    public const string WatchDashboardMethodName = "WatchDashboard";
    public const string WatchNotificationsMethodName = "WatchNotifications";

    private const string JobGroupPrefix = "job:";
    private const string UserGroupPrefix = "user:";
    private const string DashboardGroup = "dashboard";

    /// <summary>Gruppenname eines Vorgangs (Push-Seite des Notifiers).</summary>
    public static string JobGroup(Guid jobId) => JobGroupPrefix + jobId;

    /// <summary>Gruppenname eines Einreichers (Benachrichtigungen, AK-08).</summary>
    public static string UserGroup(string submittedBy) => UserGroupPrefix + submittedBy;

    /// <summary>Gruppe des Bearbeiter-Dashboards.</summary>
    public const string DashboardGroupName = DashboardGroup;

    /// <summary>
    /// Beobachtung eines Vorgangs starten. Zugriff: Eigentümer, Bearbeiter oder Admin
    /// (serverseitige Prüfung gegen den Saga-State, TM-17). Liefert den aktuellen
    /// Zustand sofort an den Aufrufer, damit die UI ohne Warteintervall synchron ist.
    /// </summary>
    public async Task WatchJob(Guid jobId)
    {
        var user = Context.User ?? throw new HubException("Nicht authentifiziert.");

        var vorgang = await reader.GetVorgangAsync(jobId, Context.ConnectionAborted);
        if (vorgang is null)
        {
            throw new HubException("Vorgang unbekannt.");
        }

        if (!VorgangAccess.CanView(user, vorgang.SubmittedBy))
        {
            throw new HubException("Kein Zugriff auf diesen Vorgang.");
        }

        await Groups.AddToGroupAsync(Context.ConnectionId, JobGroup(jobId));
        tracker.AddJobWatch(Context.ConnectionId, jobId);
        tracker.TryUpdateLastKnown(jobId, vorgang.CurrentState, vorgang.SignedArtifactId);

        await Clients.Caller.SendAsync(
            JobStatusChangedMethod,
            new JobStatusChangedEvent(jobId, vorgang.CurrentState, vorgang.SignedArtifactId, DateTimeOffset.UtcNow));
    }

    /// <summary>Beobachtung des Bearbeiter-Dashboards starten (Rolle Bearbeiter, AK-06/AK-09).</summary>
    public async Task WatchDashboard()
    {
        if (Context.User is null || !Context.User.IsInRole(PortalRoles.Editor))
        {
            throw new HubException("Dashboard erfordert die Rolle Bearbeiter.");
        }

        await Groups.AddToGroupAsync(Context.ConnectionId, DashboardGroup);
        tracker.MarkDashboardWatched(Context.ConnectionId);

        var open = await reader.GetOpenReviewsAsync(Context.ConnectionAborted);

        // Baseline des Wächters setzen: Der initiale Stand ist bereits an den Aufrufer
        // gepusht — ohne Baseline würde die erste Wächter-Änderungserkennung gegen den
        // Leer-String laufen und einen Folge-Übergang verschlucken (AK-06).
        tracker.TryUpdateDashboardFingerprint(StatusWatchTracker.FingerprintOf(open));

        var now = DateTimeOffset.UtcNow;
        await Clients.Caller.SendAsync(
            OpenReviewsChangedMethod,
            new OpenReviewsChangedEvent(open
                .Select(v => new OpenReviewItem(
                    v.JobId,
                    v.OriginalFileName,
                    v.SubmittedBy,
                    v.ReceivedAt,
                    AgeMinutes: Math.Max(0, (long)(now - v.ReceivedAt).TotalMinutes),
                    v.CurrentState,
                    v.ContentType,
                    v.FileSizeBytes))
                .ToList()));
    }

    /// <summary>Beobachtung der In-Portal-Benachrichtigungen des angemeldeten Nutzers starten (AK-08).</summary>
    public async Task WatchNotifications()
    {
        var submittedBy = Context.User?.FindFirstValue(ClaimTypes.NameIdentifier)
            ?? throw new HubException("Nicht authentifiziert.");

        await Groups.AddToGroupAsync(Context.ConnectionId, UserGroup(submittedBy));
    }

    public override Task OnDisconnectedAsync(Exception? exception)
    {
        if (tracker.RemoveConnection(Context.ConnectionId))
        {
            // Letzte Verbindung weg — Push-Basis zurücksetzen (frische Sicht beim nächsten Watch).
            tracker.ForgetLastKnown();
        }

        return base.OnDisconnectedAsync(exception);
    }
}
