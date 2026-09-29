using Microsoft.AspNetCore.SignalR;
using Microsoft.Extensions.Options;
using OfficeSelfSigningPortal.WebUI.Review;
using Ossp.Contracts;

namespace OfficeSelfSigningPortal.WebUI.LiveStatus;

/// <summary>
/// Status-Wächter für den Live-Status-Kanal (AK-02, REQ-20, IF-03): pollt den
/// read-only Saga-State-Store für die beobachteten Vorgänge und pushed
/// Zustandsänderungen an den SignalR-Hub. Single-Replica v1 — der Wächter läuft
/// in derselben Instanz wie der Hub; ein Backplane ist bewusst nicht vorgesehen
/// (REQ-20, dokumentiert im Ticket). Endzustände und Rückfragen werden zusätzlich
/// als In-Portal-Benachrichtigung an den Einreicher gepusht (AK-08).
/// </summary>
public sealed class StatusChangeNotifier(
    ISagaReviewReader reader,
    IHubContext<JobStatusHub> hub,
    StatusWatchTracker tracker,
    IOptions<LiveStatusOptions> options,
    ILogger<StatusChangeNotifier> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var interval = TimeSpan.FromSeconds(Math.Max(1, options.Value.PollIntervalSeconds));
        var timer = new PeriodicTimer(interval);
        try
        {
            while (await timer.WaitForNextTickAsync(stoppingToken))
            {
                await PushJobUpdatesAsync(stoppingToken);
                await PushDashboardUpdatesAsync(stoppingToken);
            }
        }
        catch (OperationCanceledException)
        {
            // Herunterfahren — regulärer Abbruch des Poll-Loops.
        }
    }

    private async Task PushJobUpdatesAsync(CancellationToken cancellationToken)
    {
        foreach (var jobId in tracker.WatchedJobs)
        {
            SagaVorgangInfo? vorgang;
            try
            {
                vorgang = await reader.GetVorgangAsync(jobId, cancellationToken);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                logger.LogError(ex, "Live-Status-Abfrage für JobId {JobId} fehlgeschlagen", jobId);
                continue;
            }

            if (vorgang is null)
            {
                continue;
            }

            if (!tracker.TryUpdateLastKnown(jobId, vorgang.CurrentState, vorgang.SignedArtifactId))
            {
                continue;
            }

            var changed = DateTimeOffset.UtcNow;
            await hub.Clients.Group(JobStatusHub.JobGroup(jobId)).SendAsync(
                JobStatusHub.JobStatusChangedMethod,
                new JobStatusChangedEvent(jobId, vorgang.CurrentState, vorgang.SignedArtifactId, changed),
                cancellationToken);

            // AK-08/REQ-08: Endzustand oder Rückfrage → Benachrichtigung an den Einreicher.
            if (SagaStateNames.EndStates.Contains(vorgang.CurrentState)
                || vorgang.CurrentState == SagaStateNames.RueckfrageAusstehend)
            {
                await hub.Clients.Group(JobStatusHub.UserGroup(vorgang.SubmittedBy)).SendAsync(
                    JobStatusHub.VorgangNotificationMethod,
                    new VorgangNotificationEvent(
                        jobId,
                        vorgang.OriginalFileName,
                        vorgang.CurrentState,
                        changed),
                    cancellationToken);
            }
        }
    }

    private async Task PushDashboardUpdatesAsync(CancellationToken cancellationToken)
    {
        if (!tracker.DashboardWatched)
        {
            return;
        }

        IReadOnlyList<SagaVorgangInfo> open;
        try
        {
            open = await reader.GetOpenReviewsAsync(cancellationToken);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.LogError(ex, "Dashboard-Abfrage der offenen Reviews fehlgeschlagen");
            return;
        }

        var fingerprint = StatusWatchTracker.FingerprintOf(open);
        if (!tracker.TryUpdateDashboardFingerprint(fingerprint))
        {
            return;
        }

        var now = DateTimeOffset.UtcNow;
        await hub.Clients.Group(JobStatusHub.DashboardGroupName).SendAsync(
            JobStatusHub.OpenReviewsChangedMethod,
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
                .ToList()),
            cancellationToken);
    }
}
