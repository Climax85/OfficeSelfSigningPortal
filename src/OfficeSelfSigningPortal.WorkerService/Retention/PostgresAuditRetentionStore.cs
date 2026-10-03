using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;
using Microsoft.Extensions.Logging;
using Npgsql;
using Ossp.Audit;

namespace OfficeSelfSigningPortal.WorkerService.Retention;

/// <summary>
/// EF-Core-/Npgsql-Implementierung des Audit-Löschpfads (Ticket 38, REQ-19).
/// Block-Löschung am kontinuierlichen Tabellenanfang in einer einzigen
/// Transaktion, damit die <see cref="AuditChainCheckpoint"/>-Schreibung
/// denselben Snapshot-Zustand dokumentiert. Parametrisiertes Raw SQL mit
/// Array-Parameter <c>ANY(@ids)</c> analog zu
/// <see cref="PostgresRetentionBlobStore"/> (CONVENTIONS §6).
/// </summary>
public sealed class PostgresAuditRetentionStore(
    AuditDbContext auditDb,
    ILogger<PostgresAuditRetentionStore> logger) : IAuditRetentionStore
{
    private const string DeleteCommand = """
        DELETE FROM audit_trail
        WHERE "Id" = ANY(@ids)
        """;

    public async Task<long> CountExpiredAsync(DateTimeOffset stichtag, CancellationToken cancellationToken)
    {
        return await auditDb.AuditEntries.AsNoTracking()
            .Where(e => e.OccurredAt < stichtag)
            .LongCountAsync(cancellationToken);
    }

    public async Task<AuditRetentionDeletionResult> DeleteOldestBlockAsync(
        DateTimeOffset stichtag,
        CancellationToken cancellationToken)
    {
        // Stichtag auf Mikrosekunden stutzen (analog AuditTrailWriter,
        // damit Retentions- und Hash-Vergleich denselben Timestamp-Begriff
        // teilen — sonst könnten Einträge mit truncationsbedingter Verschiebung
        // falsch eingeordnet werden).
        var gestutzt = new DateTimeOffset(stichtag.Ticks / 10 * 10, TimeSpan.Zero);

        // Kontinuierlicher Block am Tabellenanfang: alle Einträge, deren
        // OccurredAt strikt vor dem Stichtag liegt UND deren Id unter der
        // ersten Id liegt, die nicht mehr expiret (Id-Ordered-Strict
        // verhindert Lücken mitten in der Tabelle, die die Hash-Kette
        // brechen würden — siehe AuditHashChain.Verify).
        var ersteNichtAbgelaufenId = await auditDb.AuditEntries.AsNoTracking()
            .Where(e => e.OccurredAt >= gestutzt)
            .OrderBy(e => e.Id)
            .Select(e => (long?)e.Id)
            .FirstOrDefaultAsync(cancellationToken);

        if (ersteNichtAbgelaufenId is null)
        {
            // Ganze Tabelle wäre betroffen — wir lassen den jüngsten Eintrag
            // als "verbleibendes Minimum" stehen (Audit-Kette braucht einen
            // Nachfolger-Verweis; löscht man alles, ist nichts mehr zu
            // verifizieren). Die Retention-Löschung in der Praxis betrifft
            // jeweils nur den Block vor dem aktuellen Tabellenkopf.
            var juengsteId = await auditDb.AuditEntries.AsNoTracking()
                .OrderByDescending(e => e.Id)
                .Select(e => (long?)e.Id)
                .FirstOrDefaultAsync(cancellationToken);
            if (juengsteId is null)
            {
                return new AuditRetentionDeletionResult(0, string.Empty, 0);
            }

            ersteNichtAbgelaufenId = juengsteId;
        }

        var blockZumLoeschen = await auditDb.AuditEntries.AsNoTracking()
            .Where(e => e.Id < ersteNichtAbgelaufenId.Value && e.OccurredAt < gestutzt)
            .OrderBy(e => e.Id)
            .Select(e => new { e.Id, e.EntryHash })
            .ToListAsync(cancellationToken);

        if (blockZumLoeschen.Count == 0)
        {
            return new AuditRetentionDeletionResult(0, string.Empty, 0);
        }

        var lastDeletedEntryHash = blockZumLoeschen[^1].EntryHash;
        var firstRemainingEntryId = ersteNichtAbgelaufenId.Value;
        var ids = blockZumLoeschen.Select(b => b.Id).ToArray();

        // Physische Löschung des Blocks: in einer Transaktion, damit der
        // nachfolgende Checkpoint denselben konsistenten Zustand
        // dokumentiert. Idempotenz: zweiter Lauf mit identischem Stichtag
        // liefert DeletedCount = 0.
        await using var transaction = await auditDb.Database.BeginTransactionAsync(cancellationToken);
        var connection = (NpgsqlConnection)auditDb.Database.GetDbConnection();
        var eigenesOffenesConnection = false;
        if (connection.State != System.Data.ConnectionState.Open)
        {
            await connection.OpenAsync(cancellationToken);
            eigenesOffenesConnection = true;
        }

        try
        {
            await using var command = new NpgsqlCommand(DeleteCommand, connection, (NpgsqlTransaction)transaction.GetDbTransaction());
            command.Parameters.AddWithValue("ids", ids);
            await command.ExecuteNonQueryAsync(cancellationToken);
        }
        finally
        {
            if (eigenesOffenesConnection)
            {
                await connection.CloseAsync();
            }
        }

        await transaction.CommitAsync(cancellationToken);

        return new AuditRetentionDeletionResult(
            DeletedCount: blockZumLoeschen.Count,
            LastDeletedEntryHash: lastDeletedEntryHash,
            FirstRemainingEntryId: firstRemainingEntryId);
    }

    public async Task AddCheckpointAsync(AuditChainCheckpoint checkpoint, CancellationToken cancellationToken)
    {
        auditDb.ChainCheckpoints.Add(checkpoint);
        await auditDb.SaveChangesAsync(cancellationToken);
    }
}
