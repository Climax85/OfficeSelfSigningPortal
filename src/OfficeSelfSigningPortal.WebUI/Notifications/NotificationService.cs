using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using OfficeSelfSigningPortal.WebUI.Data;
using Ossp.Audit;
using Ossp.Contracts;

namespace OfficeSelfSigningPortal.WebUI.Notifications;

/// <summary>Benachrichtigungseintrag der In-Portal-Anzeige (AK-08).</summary>
/// <param name="JobId">Vorgangs-ID.</param>
/// <param name="OriginalFileName">Basisname der eingereichten Datei.</param>
/// <param name="State">Erreichten Zustand (Endzustand oder Rückfrage, Anhang B).</param>
/// <param name="Message">Fachliche Ereignisbeschreibung aus dem Audit-Trail.</param>
/// <param name="Detail">Optionale fachliche Evidenz (z. B. Rückfrage-Text).</param>
/// <param name="OccurredAt">Eintrittszeitpunkt (UTC).</param>
public sealed record NotificationItem(
    Guid JobId,
    string OriginalFileName,
    string State,
    string Message,
    string? Detail,
    DateTimeOffset OccurredAt);

public sealed record NotificationListResponse(IReadOnlyList<NotificationItem> Notifications);

/// <summary>
/// Ableitung der In-Portal-Benachrichtigungen (AK-08, UC-08, REQ-08): Der
/// manipulationsresistente Audit-Trail ist die Ereignisquelle — jeder Eintritt
/// in einen Endzustand oder eine Rückfrage ist als Saga-Audit-Eintrag
/// (<c>{Zustand}: …</c>) vorhanden. Sichtbarkeit ist auf eigene Vorgänge
/// (analysis_jobs.SubmittedBy) beschränkt.
/// </summary>
public sealed class NotificationService(
    PortalDbContext db,
    AuditDbContext auditDb,
    IOptions<NotificationOptions> options)
{
    // Anhang-B-Präfixe der benachrichtigungsrelevanten Zustände (Endzustände + Rückfrage).
    // Explizites OR statt eines aus Präfixen gebauten Ausdrucks — EF Core übersetzt
    // StartsWith als LIKE; Invoke-basierte Ausdruckskombinatoren wären nicht
    // übersetzbar. Keine Nutzereingaben in den Mustern.
    private static readonly string RueckfragePrefix = SagaStateNames.RueckfrageAusstehend + ":";
    private static readonly string SigniertPrefix = SagaStateNames.Signiert + ":";
    private static readonly string AbgelehntPrefix = SagaStateNames.Abgelehnt + ":";
    private static readonly string NichtSignierbarPrefix = SagaStateNames.NichtSignierbar + ":";
    private static readonly string FehlerPrefix = SagaStateNames.Fehler + ":";

    public async Task<IReadOnlyList<NotificationItem>> GetForUserAsync(
        string submittedBy, CancellationToken cancellationToken)
    {
        var eigeneVorgaenge = await db.AnalysisJobs.AsNoTracking()
            .Where(j => j.SubmittedBy == submittedBy)
            .Select(j => new { j.JobId, j.OriginalFileName })
            .ToListAsync(cancellationToken);
        if (eigeneVorgaenge.Count == 0)
        {
            return [];
        }

        var jobIds = eigeneVorgaenge.Select(j => j.JobId).ToArray();
        var fileNames = eigeneVorgaenge.ToDictionary(j => j.JobId, j => j.OriginalFileName);

        var eintraege = await auditDb.AuditEntries.AsNoTracking()
            .Where(e => jobIds.Contains(e.JobId) && e.Category == AuditCategories.Saga)
            .Where(e => e.Ereignis.StartsWith(RueckfragePrefix)
                || e.Ereignis.StartsWith(SigniertPrefix)
                || e.Ereignis.StartsWith(AbgelehntPrefix)
                || e.Ereignis.StartsWith(NichtSignierbarPrefix)
                || e.Ereignis.StartsWith(FehlerPrefix))
            .OrderByDescending(e => e.OccurredAt)
            .Take(options.Value.Limit)
            .ToListAsync(cancellationToken);

        return eintraege
            .Select(e => new NotificationItem(
                e.JobId,
                fileNames.GetValueOrDefault(e.JobId, string.Empty),
                StateOf(e.Ereignis),
                e.Ereignis,
                e.Detail,
                e.OccurredAt))
            .ToList();
    }

    private static string StateOf(string ereignis)
    {
        var separator = ereignis.IndexOf(':');
        return separator > 0 ? ereignis[..separator] : ereignis;
    }
}
