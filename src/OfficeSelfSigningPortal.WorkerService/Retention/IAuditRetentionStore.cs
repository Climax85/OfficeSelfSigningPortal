using Ossp.Audit;

namespace OfficeSelfSigningPortal.WorkerService.Retention;

/// <summary>
/// Löschpfad der Audit-Tabelle für den Retention-Job (Ticket 38, REQ-19,
/// Audit-Retention Obergrenze 1 Jahr). Der bestehende Audit-Schreibpfad
/// (<see cref="IAuditTrailWriter"/>) bleibt unverändert append-only; nur
/// der Retention-Job erhält einen Delete-Pfad, der zugleich die
/// sanctioned Lösch-Grenze als <see cref="AuditChainCheckpoint"/> festhält.
/// </summary>
public interface IAuditRetentionStore
{
    /// <summary>
    /// Liefert die Anzahl der Einträge, deren <c>OccurredAt</c> strikt vor
    /// <paramref name="stichtag"/> liegt. Dient als Vorprüfung
    /// (idempotente Läufe).
    /// </summary>
    Task<long> CountExpiredAsync(DateTimeOffset stichtag, CancellationToken cancellationToken);

    /// <summary>
    /// Löscht den kontinuierlichen Block am Tabellenanfang (älteste
    /// <see cref="AuditEntry"/>-Einträge nach Id), dessen <c>OccurredAt</c>
    /// strikt vor <paramref name="stichtag"/> liegt. Liefert ein Tupel aus
    /// (Anzahl gelöschter Einträge, Hash des letzten gelöschten Eintrags,
    /// Id des ersten verbleibenden Eintrags). Bei leerem Block sind
    /// <c>DeletedCount</c> = 0 und die Hash-/Id-Felder leer/0.
    /// </summary>
    Task<AuditRetentionDeletionResult> DeleteOldestBlockAsync(
        DateTimeOffset stichtag,
        CancellationToken cancellationToken);

    /// <summary>
    /// Persistiert den <see cref="AuditChainCheckpoint"/> nach erfolgreicher
    /// Löschung. Idempotent: bei zwei aufeinanderfolgenden Läufen werden
    /// zwei Zeilen geschrieben (kein dedup) — die Tabelle dokumentiert die
    /// Retention-Historie, nicht den aktuellen Zustand.
    /// </summary>
    Task AddCheckpointAsync(AuditChainCheckpoint checkpoint, CancellationToken cancellationToken);
}

/// <summary>Ergebnis von <see cref="IAuditRetentionStore.DeleteOldestBlockAsync"/>.</summary>
/// <param name="DeletedCount">Anzahl physisch gelöschter Audit-Einträge.</param>
/// <param name="LastDeletedEntryHash">SHA-256 (hex, lower) des letzten gelöschten Eintrags; leer bei <c>DeletedCount = 0</c>.</param>
/// <param name="FirstRemainingEntryId">Id des ersten Eintrags, der nach der Löschung am Tabellenanfang steht; 0 bei <c>DeletedCount = 0</c>.</param>
public sealed record AuditRetentionDeletionResult(
    long DeletedCount,
    string LastDeletedEntryHash,
    long FirstRemainingEntryId);
