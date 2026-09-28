namespace OfficeSelfSigningPortal.WorkerService.Saga;

/// <summary>
/// Schreibt Übergangs-Einträge. Best-effort: Ein Audit-Fehlversuch bricht die
/// Saga-Fortschreibung niemals ab (die Saga ist führend, REQ-11). Ticket 06 hat
/// die Persistenz in den konsolidierten, append-only hash-verketteten Audit-Trail
/// (Ossp.Audit, portal-DB) überführt; das Interface bleibt unverändert.
/// </summary>
public interface ISagaAuditWriter
{
    Task WriteAsync(
        Guid jobId,
        string zustand,
        string ereignis,
        string aktor,
        string? detail,
        CancellationToken cancellationToken);
}
