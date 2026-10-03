using System.Security.Claims;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.EntityFrameworkCore;
using OfficeSelfSigningPortal.WebUI.Authentication;
using OfficeSelfSigningPortal.WebUI.Data;
using OfficeSelfSigningPortal.WebUI.Review;
using Ossp.Audit;

namespace OfficeSelfSigningPortal.WebUI.Ingestion;

using static SubmissionOutcome;

/// <summary>API-Antworten des Submission-Endpunkts (verbindliche DTOs, englische Identifier).</summary>
/// <param name="Reason">Fachlicher Grund (z. B. Ablehnungsgrund, AK-05) — Detail des jüngsten Saga-Audit-Eintrags.</param>
/// <param name="LastEvent">Jüngster Saga-Ereignistext (Anhang-B-Übergang).</param>
/// <param name="SignedArtifactId">Referenz auf den signierten Blob, sobald vorhanden (Download, AK-04).</param>
public sealed record SubmissionStatusResponse(
    Guid JobId,
    string Status,
    string? Reason,
    string? LastEvent,
    Guid? SignedArtifactId);

public sealed record RejectionResponse(string Reason);

public sealed record UploadTokenResponse(string Token);

/// <summary>Verbindliche Zustandsnamen (Anhang B) — Quelle für Serialisierung und Tests.</summary>
public static class JobStatusNames
{
    public const string Eingereicht = nameof(JobStatus.Eingereicht);
    public const string InValidierung = nameof(JobStatus.InValidierung);
    public const string ScanLaeuft = nameof(JobStatus.ScanLaeuft);
    public const string ReviewAusstehend = nameof(JobStatus.ReviewAusstehend);
    public const string RueckfrageAusstehend = nameof(JobStatus.RueckfrageAusstehend);
    public const string SignierungAngefragt = nameof(JobStatus.SignierungAngefragt);
    public const string Signiert = nameof(JobStatus.Signiert);
    public const string Abgelehnt = nameof(JobStatus.Abgelehnt);
    public const string NichtSignierbar = nameof(JobStatus.NichtSignierbar);
    public const string Fehler = nameof(JobStatus.Fehler);
}

/// <summary>
/// Upload- und Status-Endpunkte der Ingestion (IF-01, REQ-10, REQ-23).
/// Authentifizierung zwingend (FallbackPolicy), Upload erfordert die Rolle Einreicher.
/// </summary>
public static class SubmissionEndpoints
{
    /// <summary>Named-Policy des Rate-Limits für den Upload-Kanal (TM-14, SF-03).</summary>
    public const string UploadRateLimitPolicy = "ingestion-upload";

    public static IEndpointRouteBuilder MapSubmissionEndpoints(this IEndpointRouteBuilder app)
    {
        var api = app.MapGroup("/api/submissions");

        // Antiforgery-Token-Paar (Cookie + RequestToken) für Form-Uploads; nur authentifiziert abrufbar.
        api.MapGet("/upload-token", (IAntiforgery antiforgery, HttpContext context) =>
        {
            var tokens = antiforgery.GetAndStoreTokens(context);
            return Results.Ok(new UploadTokenResponse(tokens.RequestToken ?? string.Empty));
        });

        api.MapPost("", UploadAsync)
            .RequireAuthorization(PortalAuthPolicies.Submitter)
            .RequireRateLimiting(UploadRateLimitPolicy);

        api.MapGet("/{jobId:guid}", GetStatusAsync);

        return app;
    }

    private static async Task<IResult> UploadAsync(
        IFormFile file,
        ClaimsPrincipal user,
        SubmissionService submissions,
        CancellationToken cancellationToken)
    {
        // Der Dateiname kann Client-seitig Pfadfragmente enthalten — nur der Basisname zählt.
        var originalFileName = Path.GetFileName(file.FileName);
        var submittedBy = user.FindFirstValue(ClaimTypes.NameIdentifier)
            ?? throw new InvalidOperationException("sub-Claim (NameIdentifier) fehlt im authentifizierten Principal.");
        // E-Mail-Claim des IdP (REQ-08, Ticket 10): OIDC-Mapping liefert ClaimTypes.Email,
        // Fallback auf den rohen "email"-Claim — ohne Claim bleibt die Benachrichtigungs-
        // Adresse null und der Versandpfad entscheidet selbstständig.
        var submitterEmail = user.FindFirstValue(ClaimTypes.Email) ?? user.FindFirstValue("email");

        using var memory = new MemoryStream();
        await file.CopyToAsync(memory, cancellationToken);
        var content = memory.GetBuffer().AsMemory(0, (int)memory.Length);

        var outcome = await submissions.SubmitAsync(originalFileName, content.ToArray(), submittedBy, submitterEmail, cancellationToken);

        return outcome switch
        {
            SubmissionRejected rejected => Results.UnprocessableEntity(new RejectionResponse(rejected.Reason)),
            SubmissionStored stored => Results.Created(
                $"/api/submissions/{stored.JobId}",
                new SubmissionStatusResponse(stored.JobId, stored.Status.ToString(), stored.Reason, null, null)),
            _ => throw new InvalidOperationException($"Unerwarteter Ausgang: {outcome.GetType().Name}"),
        };
    }

    private static async Task<IResult> GetStatusAsync(
        Guid jobId,
        ClaimsPrincipal user,
        SubmissionService submissions,
        ISagaReviewReader sagaReader,
        AuditDbContext auditDb,
        CancellationToken cancellationToken)
    {
        var job = await submissions.FindAsync(jobId, cancellationToken);
        var vorgang = await sagaReader.GetVorgangAsync(jobId, cancellationToken);

        // Führend ist die Saga-Zeile (Anhang B); die Upload-Zeile bleibt Fallback für
        // Vorgänge ohne Saga (makrofrei/korrupt — dort publiziert die Ingestion keine
        // ScanRequested-Nachricht).
        var submittedBy = vorgang?.SubmittedBy ?? job?.SubmittedBy;
        if (submittedBy is null)
        {
            return Results.NotFound();
        }

        // Einsicht: Eigentümer, Bearbeiter oder Admin (serverseitig, TM-17). Die
        // Erweiterung gegenüber reiner Eigentümerschaft ermöglicht den Review-
        // Kontext und den Zwei-Betrachter-Fall (AK-20, TC-40).
        if (!VorgangAccess.CanView(user, submittedBy))
        {
            return Results.Forbid();
        }

        var status = vorgang?.CurrentState ?? job!.Status.ToString();

        // AK-05: Ablehnungs-/Fehlergrund aus dem jüngsten Saga-Audit-Eintrag
        // (Detail = z. B. Review-Kommentar oder Fehlerursache); Fallback auf den
        // Grund der Upload-Zeile (Ingestion-Ablehnungen ohne Saga).
        var letztesEreignis = await auditDb.AuditEntries.AsNoTracking()
            .Where(e => e.JobId == jobId && e.Category == AuditCategories.Saga)
            .OrderByDescending(e => e.Id)
            .Select(e => new { e.Ereignis, e.Detail })
            .FirstOrDefaultAsync(cancellationToken);

        return Results.Ok(new SubmissionStatusResponse(
            jobId,
            status,
            letztesEreignis?.Detail ?? job?.StatusReason,
            letztesEreignis?.Ereignis,
            vorgang?.SignedArtifactId));
    }
}
