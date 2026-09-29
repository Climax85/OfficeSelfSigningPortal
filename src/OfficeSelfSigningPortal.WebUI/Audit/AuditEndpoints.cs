using Microsoft.EntityFrameworkCore;
using OfficeSelfSigningPortal.WebUI.Authentication;
using Ossp.Audit;

namespace OfficeSelfSigningPortal.WebUI.Audit;

/// <summary>API-Antworten des Audit-Endpunkts (verbindliche DTOs, englische Identifier).</summary>
public sealed record AuditTrailResponse(
    Guid JobId,
    bool ChainValid,
    int EntriesChecked,
    long? BrokenAtEntryId,
    string? VerificationDetail,
    IReadOnlyList<AuditEventResponse> Events);

public sealed record AuditEventResponse(
    long Id,
    DateTimeOffset OccurredAt,
    string Category,
    string Ereignis,
    string Aktor,
    string? Detail);

/// <summary>
/// Admin-Abruf des Audit-Trails (UC-07, AK-07, TC-36/TC-37, REQ-07/REQ-18): liefert
/// alle Ereignisse eines Vorgangs in zeitlicher Reihenfolge inklusive des Ergebnisses
/// der SHA-256-Hash-Ketten-Prüfung. Nur Administratoren (zentral deklarierte Policy,
/// CONVENTIONS §6). Eine ungültige Kette wird als solche gemeldet (ChainValid=false)
/// — der Abbruch des Abrufs würde die Manipulation vor dem Admin verbergen.
/// </summary>
public static class AuditEndpoints
{
    public static RouteGroupBuilder MapAuditEndpoints(this WebApplication app)
    {
        var api = app.MapGroup("/api/audit").RequireAuthorization(PortalAuthPolicies.Administrator);
        api.MapGet("/{jobId:guid}", GetAuditTrailAsync);
        return api;
    }

    private static async Task<IResult> GetAuditTrailAsync(
        Guid jobId,
        AuditDbContext db,
        CancellationToken cancellationToken)
    {
        var eintraege = await db.AuditEntries.AsNoTracking()
            .Where(e => e.JobId == jobId)
            .OrderBy(e => e.Id)
            .ToListAsync(cancellationToken);

        var erster = eintraege.FirstOrDefault();
        var ersterVorgaengerExistent = erster is null
            || AuditHashChain.GenesisPrevHash.Equals(erster.PrevHash, StringComparison.Ordinal)
            || await db.AuditEntries.AsNoTracking().AnyAsync(e => e.EntryHash == erster!.PrevHash, cancellationToken);

        var pruefung = AuditHashChain.Verify(eintraege, ersterVorgaengerExistent);

        return Results.Ok(new AuditTrailResponse(
            jobId,
            pruefung.Valid,
            pruefung.EntriesChecked,
            pruefung.BrokenAtEntryId,
            pruefung.Detail,
            eintraege.Select(e => new AuditEventResponse(
                e.Id,
                e.OccurredAt,
                e.Category,
                e.Ereignis,
                e.Aktor,
                e.Detail)).ToList()));
    }
}
