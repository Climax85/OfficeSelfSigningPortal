using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;

namespace Ossp.Audit;

/// <summary>
/// Append-only Schreibpfad des Audit-Trails (REQ-18): verkettet jeden neuen Eintrag
/// an den aktuellen Tabellenkopf. Der Schreibpfad ist bewusst serialisiert
/// (pg_advisory_xact_lock), damit parallele Services (WebUI, WorkerService,
/// SigningService) die Kette nicht durch Concurrent Appends brechen; der Lock
/// wird bei Transaktionsende automatisch freigegeben.
/// </summary>
public interface IAuditTrailWriter
{
    Task AppendAsync(
        Guid jobId,
        string category,
        string ereignis,
        string aktor,
        string? detail,
        CancellationToken cancellationToken);
}

/// <summary>
/// EF-Core-Implementierung über <see cref="IDbContextFactory{AuditDbContext}"/> —
/// auch aus synchronen Consumer-Kontexten (Saga, Guard) nutzbar. Es gibt keine
/// Update-/Delete-Methoden: Append-only ist Teil des Interfaces (TM-04).
/// </summary>
public sealed class AuditTrailWriter(
    IDbContextFactory<AuditDbContext> contextFactory,
    ILogger<AuditTrailWriter> logger) : IAuditTrailWriter
{
    // Systemweit eindeutiger Advisory-Lock ("OSSP" | 06) — serialisiert Appends
    // über alle Vorgänge und Services hinweg.
    private const long AdvisoryLockKey = 0x4F535350_0000_0006;

    public async Task AppendAsync(
        Guid jobId,
        string category,
        string ereignis,
        string aktor,
        string? detail,
        CancellationToken cancellationToken)
    {
        await using var db = await contextFactory.CreateDbContextAsync(cancellationToken);
        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);

        // Parametrisiert: ExecuteSqlAsync wandelt die Interpolation in einen DbParameter um
        // (CONVENTIONS §6). Der Lock hält exakt bis zum Transaktionsende.
        await db.Database.ExecuteSqlAsync(
            $"SELECT pg_advisory_xact_lock({AdvisoryLockKey})",
            cancellationToken);

        var prevHash = await db.AuditEntries
            .OrderByDescending(a => a.Id)
            .Select(a => a.EntryHash)
            .FirstOrDefaultAsync(cancellationToken)
            ?? AuditHashChain.GenesisPrevHash;

        var entry = new AuditEntry
        {
            JobId = jobId,
            // Auf Mikrosekunden stutzen (Präzision von timestamptz): Der gespeicherte
            // Wert muss exakt der Hash-Grundlage entsprechen, sonst bricht die
            // Ketten-Prüfung nach dem Reload (TC-37-Fehlalarm).
            OccurredAt = new DateTimeOffset(DateTimeOffset.UtcNow.Ticks / 10 * 10, TimeSpan.Zero),
            Category = category,
            Ereignis = ereignis,
            Aktor = aktor,
            Detail = detail,
            PrevHash = prevHash,
        };
        entry.EntryHash = AuditHashChain.ComputeEntryHash(entry);

        db.AuditEntries.Add(entry);
        await db.SaveChangesAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);

        logger.LogDebug(
            "Audit-Eintrag {AuditEntryId} für JobId {JobId} angehängt ({Category})",
            entry.Id,
            jobId,
            category);
    }
}
