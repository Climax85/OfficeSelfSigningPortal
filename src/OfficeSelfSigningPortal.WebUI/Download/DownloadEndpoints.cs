using System.Security.Claims;

namespace OfficeSelfSigningPortal.WebUI.Download;

/// <summary>
/// Download-Endpunkte (UC-04, AK-04, TC-27): Original ab Upload, signierte Datei
/// ab Zustand <c>Signiert</c> innerhalb des 90-Tage-Fensters. Authentifizierung
/// zwingend (FallbackPolicy), Berechtigung ausschließlich serverseitig —
/// nur der Einreicher lädt (AK-04, TM-17).
/// </summary>
public static class DownloadEndpoints
{
    private const string ContentType = "application/octet-stream";

    public static IEndpointRouteBuilder MapDownloadEndpoints(this IEndpointRouteBuilder app)
    {
        var api = app.MapGroup("/api/submissions");
        api.MapGet("/{jobId:guid}/original", DownloadOriginalAsync);
        api.MapGet("/{jobId:guid}/signed", DownloadSignedAsync);
        return api;
    }

    private static async Task<IResult> DownloadOriginalAsync(
        Guid jobId,
        ClaimsPrincipal user,
        DownloadService downloads,
        CancellationToken cancellationToken)
    {
        var currentUser = SubOf(user);
        var outcome = await downloads.GetOriginalAsync(jobId, currentUser, cancellationToken);

        return outcome switch
        {
            OriginalDownloadOutcome.Available(var content, var fileName)
                => Results.File(content, ContentType, fileDownloadName: Path.GetFileName(fileName)),
            OriginalDownloadOutcome.Unknown => Results.NotFound(),
            OriginalDownloadOutcome.Forbidden => Results.Forbid(),
            OriginalDownloadOutcome.Gone => Results.StatusCode(StatusCodes.Status410Gone),
            _ => throw new InvalidOperationException($"Unerwarteter Ausgang: {outcome.GetType().Name}"),
        };
    }

    private static async Task<IResult> DownloadSignedAsync(
        Guid jobId,
        ClaimsPrincipal user,
        DownloadService downloads,
        CancellationToken cancellationToken)
    {
        var currentUser = SubOf(user);
        var outcome = await downloads.GetSignedAsync(jobId, currentUser, cancellationToken);

        return outcome switch
        {
            SignedDownloadOutcome.Available(var content, var fileName)
                => Results.File(content, ContentType, fileDownloadName: Path.GetFileName(fileName)),
            SignedDownloadOutcome.Unknown => Results.NotFound(),
            SignedDownloadOutcome.Forbidden => Results.Forbid(),
            SignedDownloadOutcome.NotSigned(var state)
                => Results.Conflict(new { Reason = $"Vorgang ist nicht signiert (Status: {state})." }),
            SignedDownloadOutcome.Expired
                => Results.StatusCode(StatusCodes.Status410Gone),
            SignedDownloadOutcome.Gone
                => Results.StatusCode(StatusCodes.Status410Gone),
            _ => throw new InvalidOperationException($"Unerwarteter Ausgang: {outcome.GetType().Name}"),
        };
    }

    private static string SubOf(ClaimsPrincipal user)
        => user.FindFirstValue(ClaimTypes.NameIdentifier)
           ?? throw new InvalidOperationException("sub-Claim (NameIdentifier) fehlt im authentifizierten Principal.");
}
