using MassTransit;
using Microsoft.EntityFrameworkCore;
using Ossp.Audit;
using Ossp.Contracts;
using OfficeSelfSigningPortal.WebUI.Data;

namespace OfficeSelfSigningPortal.WebUI.Review;

/// <summary>
/// Verdrahtet Review-Intake und Publikation: Die Vertragsnachrichten
/// (<see cref="ReviewDecisionRecorded"/>, <see cref="EinreicherAntwortEingegangen"/>)
/// werden über die EF-Core-Outbox gestaged (REQ-11, TM-06) — SaveChanges flusht
/// sie in derselben Transaktion; der Bus-Outbox-Delivery-Service publiziert sie
/// an die Saga. Aktive Inhalte werden vor dem Staging gefiltert (AK-49).
/// Der Intake schreibt je einen Audit-Eintrag (Kategorie <see cref="AuditCategories.Review"/>,
/// TM-07/REQ-18, best-effort wie in SubmissionService/Guard dokumentiert).
/// </summary>
public sealed class ReviewService(
    PortalDbContext db,
    IPublishEndpoint publishEndpoint,
    IAuditTrailWriter auditTrail,
    ILogger<ReviewService> logger)
{
    public async Task RecordDecisionAsync(
        Guid jobId, string reviewerId, string decision, string? comment, CancellationToken cancellationToken)
    {
        // Kommentar/Begründung zieht denselben XSS-Filter wie die Rückfrage-Antwort
        // (Ablehnungsgründe werden im Portal angezeigt, AK-05).
        var sanitizedComment = comment is null ? null : RueckfrageTextSanitizer.Sanitize(comment);

        await publishEndpoint.Publish(
            new ReviewDecisionRecorded(jobId, reviewerId, decision, sanitizedComment, DateTimeOffset.UtcNow),
            cancellationToken);
        await db.SaveChangesAsync(cancellationToken);

        await AuditIntakeAsync(
            jobId,
            $"Review-Entscheidung aufgenommen: {decision}",
            reviewerId,
            sanitizedComment,
            cancellationToken);
    }

    public async Task RecordAnswerAsync(
        Guid jobId, string answer, string submittedBy, CancellationToken cancellationToken)
    {
        var sanitizedAnswer = RueckfrageTextSanitizer.Sanitize(answer);

        await publishEndpoint.Publish(
            new EinreicherAntwortEingegangen(jobId, sanitizedAnswer, submittedBy, DateTimeOffset.UtcNow),
            cancellationToken);
        await db.SaveChangesAsync(cancellationToken);

        await AuditIntakeAsync(
            jobId,
            "Einreicher-Antwort aufgenommen",
            submittedBy,
            sanitizedAnswer,
            cancellationToken);
    }

    /// <summary>
    /// Protokolliert eine abgewiesene Review-Operation als Sicherheitsvorfall
    /// (Kategorie <see cref="AuditCategories.Guard"/>, Vorbild: SignMacroRequestGuardConsumer) —
    /// best-effort: Ein Protokoll-Fehlversuch darf die Ablehnung selbst nicht kippen.
    /// </summary>
    public async Task AuditRejectionAsync(
        Guid jobId, string aktor, string ereignis, CancellationToken cancellationToken)
    {
        try
        {
            await auditTrail.AppendAsync(jobId, AuditCategories.Guard, ereignis, aktor, detail: null, cancellationToken);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.LogError(ex, "Guard-Eintrag für JobId {JobId} ({Ereignis}) konnte nicht geschrieben werden", jobId, ereignis);
        }
    }

    private async Task AuditIntakeAsync(
        Guid jobId, string ereignis, string aktor, string? detail, CancellationToken cancellationToken)
    {
        try
        {
            await auditTrail.AppendAsync(jobId, AuditCategories.Review, ereignis, aktor, detail, cancellationToken);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.LogError(ex, "Review-Intake-Audit für JobId {JobId} konnte nicht geschrieben werden", jobId);
        }
    }
}
