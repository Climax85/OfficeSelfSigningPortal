namespace OfficeSelfSigningPortal.WorkerService.Saga;

/// <summary>
/// Audit-Eintrag je Saga-Übergang (Anhang B: "jeder Übergang schreibt einen
/// Audit-Trail-Eintrag", REQ-18). Ticket 06 baut daraus die append-only,
/// SHA-256-hash-verkettete Fassung auf (TC-36/TC-37); Tabelle und Schreibpfad
/// bleiben bewusst minimal, damit Ticket 06 Schema und Erzwingung festlegt.
/// </summary>
public sealed class SagaAuditEntry
{
    public long Id { get; set; }
    public Guid JobId { get; set; }
    public DateTimeOffset OccurredAt { get; set; }
    public string Zustand { get; set; } = string.Empty;
    public string Ereignis { get; set; } = string.Empty;
    public string Aktor { get; set; } = string.Empty;
    public string? Detail { get; set; }
}

/// <summary>
/// Schreibt Übergangs-Einträge. Best-effort: Ein Audit-Fehlversuch bricht die
/// Saga-Fortschreibung niemals ab (die Saga ist führend, REQ-11).
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
