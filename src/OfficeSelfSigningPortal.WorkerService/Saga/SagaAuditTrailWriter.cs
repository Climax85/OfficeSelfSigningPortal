using Microsoft.Extensions.Logging;
using Ossp.Audit;

namespace OfficeSelfSigningPortal.WorkerService.Saga;

/// <summary>
/// Schreibt Saga-Übergänge (Anhang B: "jeder Übergang schreibt einen Audit-Trail-
/// Eintrag", REQ-18) in den konsolidierten Audit-Trail (Ticket 06): append-only,
/// SHA-256-hash-verkettet, portal-DB. Best-effort (siehe Interface-Doku) — eine
/// Nachweislücke ist später als Kettenbruch sichtbar (TM-04).
/// </summary>
public sealed class SagaAuditTrailWriter(
    IAuditTrailWriter auditTrail,
    ILogger<SagaAuditTrailWriter> logger) : ISagaAuditWriter
{
    public async Task WriteAsync(
        Guid jobId,
        string zustand,
        string ereignis,
        string aktor,
        string? detail,
        CancellationToken cancellationToken)
    {
        try
        {
            await auditTrail.AppendAsync(
                jobId,
                AuditCategories.Saga,
                $"{zustand}: {ereignis}",
                aktor,
                detail,
                cancellationToken);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.LogError(ex, "Audit-Eintrag für JobId {JobId} ({Zustand}) konnte nicht geschrieben werden", jobId, zustand);
        }
    }
}
