using MassTransit;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using OfficeSelfSigningPortal.WebUI.Data;
using Ossp.Audit;
using Ossp.Contracts;

namespace OfficeSelfSigningPortal.WebUI.Ingestion;

using static IngestionVerdict;
using static SubmissionOutcome;

/// <summary>
/// Verdrahtet Validierung und Persistierung eines Uploads.
/// Der gültige Upload erzeugt den persistierten Analyseauftrag als ScanRequested-
/// Datensatz (Anhang A, inkl. ContentSha256 als TOCTOU-Basis) und publiziert ihn
/// über die EF-Core-Outbox (REQ-11, TM-06): Staging vor SaveChanges, die Nachricht
/// committet atomar mit dem Upload und startet die Saga im WorkerService.
/// </summary>
public sealed class SubmissionService(
    PortalDbContext db,
    IPublishEndpoint publishEndpoint,
    IOptions<IngestionOptions> options,
    IAuditTrailWriter auditTrail,
    ILogger<SubmissionService> logger)
{
    private const string MacroFreeHint = "Kein Makro enthalten: Die Datei ist makrofrei und muss nicht signiert werden.";

    public async Task<SubmissionOutcome> SubmitAsync(
        string originalFileName, byte[] content, string submittedBy, CancellationToken cancellationToken)
    {
        var verdict = IngestionValidator.Validate(originalFileName, content, options.Value);

        if (verdict is Rejected rejected)
        {
            // Upload-Regel verletzt: Ablehnung mit Grund, kein Vorgang, kein Scan (REQ-10/REQ-23).
            // Ablehnungen sind sicherheitsrelevante Ereignisse und werden protokolliert (kein Dateiinhalt).
            logger.LogInformation(
                "Upload abgelehnt ({ReasonCode}) von {SubmittedBy}: {OriginalFileName}",
                rejected.ReasonCode,
                submittedBy,
                originalFileName);
            return new SubmissionRejected(rejected.Reason);
        }

        var now = DateTimeOffset.UtcNow;
        var artifactId = Guid.NewGuid();
        var contentSha256 = verdict is Accepted accepted
            ? accepted.ContentSha256
            : Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(content));

        // ScanRequested (Anhang A) ist der führende Datensatz des Analyseauftrags.
        var scanRequested = new ScanRequested(
            JobId: Guid.NewGuid(),
            ArtifactId: artifactId,
            ContentSha256: contentSha256,
            OriginalFileName: originalFileName,
            ContentType: verdict is Accepted a ? a.ContentType : string.Empty,
            FileSizeBytes: content.LongLength,
            SubmittedBy: submittedBy,
            RequestedAt: now);

        var (status, reason) = verdict switch
        {
            Accepted => (JobStatus.Eingereicht, (string?)null),
            MacroFree => (JobStatus.NichtSignierbar, MacroFreeHint),
            Corrupt corrupt => (JobStatus.Fehler, corrupt.TechnicalReason),
            _ => throw new InvalidOperationException($"Unerwartetes Verdict: {verdict.GetType().Name}"),
        };

        db.Artifacts.Add(new Artifact
        {
            ArtifactId = artifactId,
            Content = content,
            ContentSha256 = contentSha256,
        });

        db.AnalysisJobs.Add(new AnalysisJob
        {
            JobId = scanRequested.JobId,
            ArtifactId = artifactId,
            SubmittedBy = submittedBy,
            OriginalFileName = originalFileName,
            ContentType = scanRequested.ContentType,
            FileSizeBytes = scanRequested.FileSizeBytes,
            ContentSha256 = contentSha256,
            Status = status,
            StatusReason = reason,
            CreatedAt = now,
        });

        if (verdict is Accepted)
        {
            // Outbox statt direktem Publish (REQ-11, TM-06): Der Outbox-Interceptor
            // schreibt die Nachricht bei SaveChanges in derselben Transaktion —
            // ein Crash zwischen Upload und Publikation verliert den Scanauftrag nicht.
            await publishEndpoint.Publish(scanRequested, cancellationToken);
        }

        await db.SaveChangesAsync(cancellationToken);

        // Upload ist ein vorgangsrelevantes Ereignis (REQ-18, AK-48): append-only
        // in die SHA-256-Hash-Kette (TM-04). Best-effort — ein Audit-Fehlversuch
        // bricht den Upload nicht ab (Nachweislücke ist kettenbruch-sichtbar).
        try
        {
            await auditTrail.AppendAsync(
                scanRequested.JobId,
                AuditCategories.Upload,
                "Upload persistiert",
                submittedBy,
                originalFileName,
                cancellationToken);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.LogError(ex, "Audit-Eintrag für Upload {JobId} konnte nicht geschrieben werden", scanRequested.JobId);
        }

        if (verdict is Corrupt corruptVerdict)
        {
            logger.LogWarning(
                "Korrumpierter Upload von {SubmittedBy}: {OriginalFileName} — {TechnicalReason}",
                submittedBy,
                originalFileName,
                corruptVerdict.TechnicalReason);
        }

        return new SubmissionStored(scanRequested.JobId, status, reason);
    }

    public async Task<AnalysisJob?> FindAsync(Guid jobId, CancellationToken cancellationToken)
        => await db.AnalysisJobs.AsNoTracking().FirstOrDefaultAsync(j => j.JobId == jobId, cancellationToken);
}

/// <summary>Ausgang einer Upload-Einreichung (HTTP-Projektion im Endpunkt).</summary>
public abstract record SubmissionOutcome
{
    /// <summary>Ablehnung mit Grund — kein Vorgang angelegt.</summary>
    public sealed record SubmissionRejected(string Reason) : SubmissionOutcome;

    /// <summary>Vorgang persistiert (Eingereicht/NichtSignierbar/Fehler).</summary>
    public sealed record SubmissionStored(Guid JobId, JobStatus Status, string? Reason) : SubmissionOutcome;
}
