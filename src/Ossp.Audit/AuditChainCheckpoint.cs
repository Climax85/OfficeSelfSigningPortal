namespace Ossp.Audit;

/// <summary>
/// Sanctioned deletion boundary in the audit hash chain (Ticket 38, REQ-19,
/// Audit-Retention Obergrenze 1 Jahr). The retention job physically deletes
/// the oldest entries older than the configured limit; the first remaining
/// entry's <see cref="AuditEntry.PrevHash"/> would otherwise point to a
/// hash that is no longer in the table — breaking the per-job first-entry
/// check in <see cref="AuditHashChain.Verify"/>. The checkpoint records
/// the hash of the last deleted entry, allowing the Admin endpoint to
/// recognise the boundary as a known, sanctioned gap in the chain rather
/// than a manipulation.
///
/// The checkpoint table is intentionally narrow: one row per retention
/// run, no per-job bookkeeping. It is not a substitute for the audit
/// trail itself; the retention run is also audit-protocolled via a
/// regular <see cref="AuditEntry"/> (Category "deletion", Aktor
/// "system:retention") so that the deletion event remains part of the
/// chain and is queryable by Admin.
/// </summary>
public sealed class AuditChainCheckpoint
{
    public long Id { get; set; }

    /// <summary>UTC timestamp of the retention run that produced the boundary.</summary>
    public DateTimeOffset SetAt { get; set; }

    /// <summary>
    /// SHA-256 (hex, lower) of the last entry that was deleted. Used by
    /// the Admin endpoint to accept the new first-entry-of-table's
    /// <see cref="AuditEntry.PrevHash"/> as a known, sanctioned reference
    /// instead of a manipulation signal.
    /// </summary>
    public string LastDeletedEntryHash { get; set; } = string.Empty;

    /// <summary>Id of the first entry that remained after the deletion (long, for traceability).</summary>
    public long FirstRemainingEntryId { get; set; }

    /// <summary>Number of audit entries physically deleted by this run.</summary>
    public long DeletedCount { get; set; }

    /// <summary>Akteur, der die Retention ausgelöst hat (konstant "system:retention" im Automatikbetrieb).</summary>
    public string Aktor { get; set; } = string.Empty;

    /// <summary>Fachliche Begründung (z. B. "audit-retention-1y") — aus RetentionOptions abgeleitet.</summary>
    public string Reason { get; set; } = string.Empty;
}
