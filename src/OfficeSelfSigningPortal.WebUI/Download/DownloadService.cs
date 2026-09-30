using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using OfficeSelfSigningPortal.WebUI.Data;
using OfficeSelfSigningPortal.WebUI.Review;
using Ossp.Audit;
using Ossp.Contracts;

namespace OfficeSelfSigningPortal.WebUI.Download;

/// <summary>Ausgang eines signierten Downloads (HTTP-Projektion im Endpunkt).</summary>
public abstract record SignedDownloadOutcome
{
    /// <summary>Blob und Anzeigename liegen vor.</summary>
    public sealed record Available(byte[] Content, string FileName) : SignedDownloadOutcome;

    /// <summary>Vorgang unbekannt (keine Saga-Zeile).</summary>
    public sealed record Unknown : SignedDownloadOutcome;

    /// <summary>Nur der Einreicher darf laden (AK-04).</summary>
    public sealed record Forbidden : SignedDownloadOutcome;

    /// <summary>Vorgang ist nicht (mehr) im Zustand <c>Signiert</c>.</summary>
    public sealed record NotSigned(string CurrentState) : SignedDownloadOutcome;

    /// <summary>Der 90-Tage-Downloadzeitraum ist abgelaufen (AK-04, REQ-19).</summary>
    public sealed record Expired : SignedDownloadOutcome;

    /// <summary>Zeitstempel oder Blob der Signierung fehlt (Retention bereits gelöscht).</summary>
    public sealed record Gone : SignedDownloadOutcome;
}

/// <summary>Ausgang eines Original-Downloads (HTTP-Projektion im Endpunkt).</summary>
public abstract record OriginalDownloadOutcome
{
    public sealed record Available(byte[] Content, string FileName) : OriginalDownloadOutcome;
    public sealed record Unknown : OriginalDownloadOutcome;
    public sealed record Forbidden : OriginalDownloadOutcome;

    /// <summary>Der Original-Blob wurde vom Retention-Job gelöscht (AK-19, Ticket 11).</summary>
    public sealed record Gone : OriginalDownloadOutcome;
}

/// <summary>
/// Verdrahtung der Vorgangs-Downloads (UC-04, AK-04, TC-27): Der führende Status
/// stammt aus dem Saga-State-Store; der Signatur-Zeitstempel aus dem Audit-Trail
/// (Eintrag <c>Signiert: …</c>) — die Saga-Zeile führt keinen Zeitstempel des
/// Eintritts. Die Blobs liegen in der portal-DB (EF-Pfad, eigener Kontext).
/// </summary>
public sealed class DownloadService(
    PortalDbContext db,
    AuditDbContext auditDb,
    ISagaReviewReader reader,
    IOptions<DownloadOptions> options)
{
    public async Task<OriginalDownloadOutcome> GetOriginalAsync(
        Guid jobId, string currentUser, CancellationToken cancellationToken)
    {
        var job = await db.AnalysisJobs.AsNoTracking()
            .Include(j => j.Artifact)
            .FirstOrDefaultAsync(j => j.JobId == jobId, cancellationToken);
        if (job is null)
        {
            return new OriginalDownloadOutcome.Unknown();
        }

        if (job.Artifact is null)
        {
            // Retention (Ticket 11) hat den Original-Blob bereits entfernt (AK-19).
            return new OriginalDownloadOutcome.Gone();
        }

        if (!string.Equals(job.SubmittedBy, currentUser, StringComparison.Ordinal))
        {
            return new OriginalDownloadOutcome.Forbidden();
        }

        return new OriginalDownloadOutcome.Available(job.Artifact.Content, job.OriginalFileName);
    }

    public async Task<SignedDownloadOutcome> GetSignedAsync(
        Guid jobId, string currentUser, CancellationToken cancellationToken)
    {
        var vorgang = await reader.GetVorgangAsync(jobId, cancellationToken);
        if (vorgang is null)
        {
            return new SignedDownloadOutcome.Unknown();
        }

        if (!string.Equals(vorgang.SubmittedBy, currentUser, StringComparison.Ordinal))
        {
            return new SignedDownloadOutcome.Forbidden();
        }

        if (vorgang.CurrentState != SagaStateNames.Signiert || vorgang.SignedArtifactId is null)
        {
            return new SignedDownloadOutcome.NotSigned(vorgang.CurrentState);
        }

        // Signatur-Zeitstempel: jüngster Saga-Audit-Eintrag zum Eintritt von Signiert.
        var signedAt = await auditDb.AuditEntries.AsNoTracking()
            .Where(e => e.JobId == jobId
                && e.Category == AuditCategories.Saga
                && e.Ereignis.StartsWith(SagaStateNames.Signiert + ":"))
            .OrderByDescending(e => e.Id)
            .Select(e => (DateTimeOffset?)e.OccurredAt)
            .FirstOrDefaultAsync(cancellationToken);
        if (signedAt is null)
        {
            return new SignedDownloadOutcome.Gone();
        }

        if (signedAt.Value.AddDays(options.Value.SignedDownloadRetentionDays) < DateTimeOffset.UtcNow)
        {
            return new SignedDownloadOutcome.Expired();
        }

        var blob = await db.Artifacts.AsNoTracking()
            .FirstOrDefaultAsync(a => a.ArtifactId == vorgang.SignedArtifactId.Value, cancellationToken);
        if (blob is null)
        {
            // Retention (Ticket 11) hat den Blob bereits entfernt.
            return new SignedDownloadOutcome.Gone();
        }

        return new SignedDownloadOutcome.Available(blob.Content, SignedFileName(vorgang.OriginalFileName));
    }

    /// <summary>Ableitung des Anzeigenamens der signierten Datei (Basisname bleibt erhalten).</summary>
    private static string SignedFileName(string originalFileName)
    {
        var basename = Path.GetFileName(originalFileName);
        var stem = Path.GetFileNameWithoutExtension(basename);
        var extension = Path.GetExtension(basename);
        return $"{stem}-signiert{extension}";
    }
}
