using System.Security.Claims;
using Microsoft.Extensions.Options;
using OfficeSelfSigningPortal.WebUI.Authentication;
using Ossp.Contracts;

namespace OfficeSelfSigningPortal.WebUI.Review;

/// <summary>API-Antworten des Review-Endpunkts (verbindliche DTOs, englische Identifier).</summary>
public sealed record OpenReviewItem(
    Guid JobId,
    string OriginalFileName,
    string SubmittedBy,
    DateTimeOffset SubmittedAt,
    long AgeMinutes,
    string CurrentState,
    string ContentType,
    long FileSizeBytes);

public sealed record OpenReviewsResponse(IReadOnlyList<OpenReviewItem> Reviews);

/// <summary>Anfragekörper einer Review-Entscheidung (Anhang A — exakt drei Werte).</summary>
public sealed record ReviewDecisionRequest(string? Decision, string? Comment);

/// <summary>Anfragekörper einer Rückfrage-Antwort des Einreichers (Plaintext).</summary>
public sealed record RueckfrageAnswerRequest(string? Answer);

/// <summary>Fehlerantwort der Review-API mit fachlichem Grund (keine Exception-Texte).</summary>
public sealed record ReviewErrorResponse(string Reason);

/// <summary>
/// Review-API (UC-03, REQ-03/06/17): Bearbeiter-Dashboard-Daten und Verdrahtung
/// der Review-Entscheidungen (Ticket 07). Freigabe/Ablehnen/Rückfrage selbst führt
/// die Saga im WorkerService aus (Anhang B) — die API publiziert die Vertrags-
/// Nachrichten über die EF-Core-Outbox (REQ-11, TM-06).
/// </summary>
public static class ReviewEndpoints
{
    /// <summary>Named-Policy des Rate-Limits für den Rückfrage-Kanal (TM-02).</summary>
    public const string RueckfrageRateLimitPolicy = "rueckfrage-kanal";

    public static IEndpointRouteBuilder MapReviewEndpoints(this IEndpointRouteBuilder app)
    {
        var api = app.MapGroup("/api/reviews");

        api.MapGet("/open", GetOpenReviewsAsync)
            .RequireAuthorization(PortalAuthPolicies.Editor);

        // Kein RequireAuthorization(Editor) am Decision-Endpunkt: TC-25/AK-09 verlangt
        // die Protokollierung des Vorfalls — dafür muss der Handler erreicht werden
        // (FallbackPolicy sorgt für 401 bei anonym; die Rollenprüfung läuft im Handler).
        api.MapPost("/{jobId:guid}/decision", DecideAsync);

        api.MapPost("/{jobId:guid}/answer", AnswerAsync)
            .RequireRateLimiting(RueckfrageRateLimitPolicy);

        return app;
    }

    private static async Task<IResult> GetOpenReviewsAsync(
        ISagaReviewReader reader,
        CancellationToken cancellationToken)
    {
        var vorgaenge = await reader.GetOpenReviewsAsync(cancellationToken);
        var now = DateTimeOffset.UtcNow;

        return Results.Ok(new OpenReviewsResponse(vorgaenge
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

    private static async Task<IResult> DecideAsync(
        Guid jobId,
        ReviewDecisionRequest request,
        ClaimsPrincipal user,
        ISagaReviewReader reader,
        ReviewService reviews,
        IOptions<ReviewOptions> options,
        ILoggerFactory loggerFactory,
        CancellationToken cancellationToken)
    {
        var reviewerId = user.FindFirstValue(ClaimTypes.NameIdentifier)
            ?? throw new InvalidOperationException("sub-Claim (NameIdentifier) fehlt im authentifizierten Principal.");
        var logger = loggerFactory.CreateLogger("OfficeSelfSigningPortal.WebUI.Review.Decision");

        // TC-25/AK-09: Entscheidung ohne Bearbeiter-Rolle → 403, keine Zustandsänderung,
        // Vorfall protokolliert (Guard-Audit + strukturiertes Log).
        if (!user.IsInRole(PortalRoles.Editor))
        {
            logger.LogWarning(
                "Review-Entscheidung für JobId {JobId} von {Aktor} ohne Bearbeiter-Rolle abgelehnt (Decision: {Decision})",
                jobId,
                reviewerId,
                request.Decision ?? "<fehlt>");
            await reviews.AuditRejectionAsync(
                jobId, reviewerId, "Review-Entscheidung ohne Bearbeiter-Rolle abgelehnt", cancellationToken);
            return Results.Forbid();
        }

        // Validierung am Systemrand (CONVENTIONS §5).
        if (request.Decision is not (
                ReviewDecisionValues.Freigeben
                or ReviewDecisionValues.Ablehnen
                or ReviewDecisionValues.Rueckfrage))
        {
            return Results.UnprocessableEntity(
                new ReviewErrorResponse($"Ungültige Entscheidung — erlaubt: {ReviewDecisionValues.Freigeben}, {ReviewDecisionValues.Ablehnen}, {ReviewDecisionValues.Rueckfrage}."));
        }

        if (request.Decision == ReviewDecisionValues.Ablehnen && string.IsNullOrWhiteSpace(request.Comment))
        {
            return Results.UnprocessableEntity(
                new ReviewErrorResponse("Ablehnen erfordert eine Begründung (Comment)."));
        }

        if (request.Comment is not null && request.Comment.Length > options.Value.MaxCommentLength)
        {
            return Results.UnprocessableEntity(
                new ReviewErrorResponse($"Kommentar überschreitet das Limit von {options.Value.MaxCommentLength} Zeichen."));
        }

        var vorgang = await reader.GetVorgangAsync(jobId, cancellationToken);
        if (vorgang is null)
        {
            return Results.NotFound();
        }

        // Anhang B: Entscheidungen sind ausschließlich aus ReviewAusstehend definiert —
        // sonst würde die Saga die Nachricht unbehandelt verwerfen (kein Audit-Ereignis).
        if (!string.Equals(vorgang.CurrentState, SagaStateNames.ReviewAusstehend, StringComparison.Ordinal))
        {
            return Results.Conflict(new ReviewErrorResponse(
                $"Vorgang ist nicht im Review ({vorgang.CurrentState}) — Entscheidung nicht möglich."));
        }

        // SoD-Frühabweisung (TC-22, AK-17, TM-18): Die Saga bleibt der letzte
        // Sicherheitsring (lehnt ReviewerId == SubmitterId ebenfalls ab).
        if (request.Decision == ReviewDecisionValues.Freigeben
            && string.Equals(vorgang.SubmittedBy, reviewerId, StringComparison.Ordinal))
        {
            logger.LogWarning(
                "SoD-Verletzung am Review-API für JobId {JobId}: Freigabeversuch durch Einreicher {Aktor}",
                jobId,
                reviewerId);
            await reviews.AuditRejectionAsync(
                jobId, reviewerId, "SoD-Verletzung: Freigabe durch Einreicher am Review-API abgelehnt", cancellationToken);
            return Results.Conflict(new ReviewErrorResponse(
                "Separation of Duties: Einreicher können ihre eigene Datei nicht freigeben."));
        }

        await reviews.RecordDecisionAsync(jobId, reviewerId, request.Decision, request.Comment, cancellationToken);
        return Results.Accepted($"/api/reviews/{jobId}");
    }

    private static async Task<IResult> AnswerAsync(
        Guid jobId,
        RueckfrageAnswerRequest request,
        ClaimsPrincipal user,
        ISagaReviewReader reader,
        ReviewService reviews,
        IOptions<ReviewOptions> options,
        CancellationToken cancellationToken)
    {
        var currentUser = user.FindFirstValue(ClaimTypes.NameIdentifier)
            ?? throw new InvalidOperationException("sub-Claim (NameIdentifier) fehlt im authentifizierten Principal.");

        if (string.IsNullOrWhiteSpace(request.Answer))
        {
            return Results.UnprocessableEntity(new ReviewErrorResponse("Antwort darf nicht leer sein."));
        }

        if (request.Answer.Length > options.Value.MaxAnswerLength)
        {
            return Results.UnprocessableEntity(
                new ReviewErrorResponse($"Antwort überschreitet das Limit von {options.Value.MaxAnswerLength} Zeichen."));
        }

        var vorgang = await reader.GetVorgangAsync(jobId, cancellationToken);
        if (vorgang is null)
        {
            return Results.NotFound();
        }

        // Der Rückfrage-Kanal gehört dem Einreicher — fremde Antworten werden verworfen.
        if (!string.Equals(vorgang.SubmittedBy, currentUser, StringComparison.Ordinal))
        {
            return Results.Forbid();
        }

        // Anhang B: Antworten sind ausschließlich aus RueckfrageAusstehend definiert.
        if (!string.Equals(vorgang.CurrentState, SagaStateNames.RueckfrageAusstehend, StringComparison.Ordinal))
        {
            return Results.Conflict(new ReviewErrorResponse(
                $"Für den Vorgang liegt keine Rückfrage vor ({vorgang.CurrentState})."));
        }

        await reviews.RecordAnswerAsync(jobId, request.Answer, currentUser, cancellationToken);
        return Results.Accepted($"/api/reviews/{jobId}");
    }
}
