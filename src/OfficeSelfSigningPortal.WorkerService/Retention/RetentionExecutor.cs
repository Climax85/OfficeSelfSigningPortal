using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using OfficeSelfSigningPortal.WorkerService.Data;
using Ossp.Audit;
using Ossp.Contracts;

namespace OfficeSelfSigningPortal.WorkerService.Retention;

/// <summary>
/// Fachliche Kernlogik des Retention-Jobs (Ticket 11, REQ-19, AK-19, TC-38):
///
/// 1. <b>Blob-Retention</b> — Vorgänge, deren Signierung länger als die
///    konfigurierbare Frist (Default 90 Tage) zurückliegt, verlieren ihre
///    Blob-Daten (Original + signierte Datei). Der Signatur-Zeitstempel
///    stammt aus dem Audit-Trail (jüngster Saga-Eintrag zum Eintritt von
///    <c>Signiert</c>) — dieselbe Basis wie das Download-Fenster der
///    WebUI (Verteidigung in der Tiefe).
///
/// 2. <b>Audit-Retention</b> (Ticket 38, REQ-19, AK-19): Audit-Einträge
///    werden nach Ablauf der konfigurierbaren Frist (Default 1 Jahr) am
///    kontinuierlichen Tabellenanfang gelöscht. Die sanctioned Lösch-Grenze
///    wird in <c>audit_chain_checkpoints</c> festgehalten, damit die
///    Hash-Ketten-Prüfung beim Admin-Abruf die Lücke als sanctioned
///    erkennt (REQ-18, AK-07, AK-18). Die Löschung selbst wird als
///    Audit-Eintrag protokolliert (REQ-18, Aktor <c>system:retention</c>).
///
/// Beide Pfade laufen über denselben <see cref="TimeProvider"/> (fälschbar)
/// und sind idempotent (zweiter Lauf ohne neue abgelaufene Einträge
/// verändert den Zustand nicht).
/// </summary>
public sealed class RetentionExecutor(
    WorkerDbContext workerDb,
    AuditDbContext auditDb,
    IRetentionBlobStore blobStore,
    IAuditRetentionStore auditRetentionStore,
    IAuditTrailWriter auditTrail,
    IOptions<RetentionOptions> options,
    TimeProvider timeProvider,
    ILogger<RetentionExecutor> logger)
{
    public async Task ExecuteAsync(CancellationToken cancellationToken)
    {
        await LöscheAbgelaufeneBlobsAsync(cancellationToken);
        await LöscheAbgelaufeneAuditEintraegeAsync(cancellationToken);
    }

    private async Task LöscheAbgelaufeneBlobsAsync(CancellationToken cancellationToken)
    {
        var stichtag = timeProvider.GetUtcNow().AddDays(-options.Value.BlobRetentionDays);

        // Fällige Vorgänge: Signatur-Eintrag im Audit-Trail mindestens frist-alt.
        // Der Eintritt in "Signiert" ist ein Endzustand — jüngster Eintrag zählt
        // (duplikatsicher), analog zum Download-Fenster der WebUI.
        var fälligeJobIds = await auditDb.AuditEntries.AsNoTracking()
            .Where(e => e.Category == AuditCategories.Saga
                && e.Ereignis.StartsWith(SagaStateNames.Signiert + ":")
                && e.OccurredAt <= stichtag)
            .Select(e => e.JobId)
            .Distinct()
            .ToListAsync(cancellationToken);

        foreach (var jobId in fälligeJobIds)
        {
            // Ein Fehler an einem Vorgang darf die übrigen nicht blockieren.
            try
            {
                await LöscheVorgangBlobsAsync(jobId, cancellationToken);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                logger.LogError(ex, "Blob-Retention-Löschung für JobId {JobId} fehlgeschlagen", jobId);
            }
        }
    }

    private async Task LöscheVorgangBlobsAsync(Guid jobId, CancellationToken cancellationToken)
    {
        var saga = await workerDb.SagaStates.AsNoTracking()
            .FirstOrDefaultAsync(s => s.CorrelationId == jobId, cancellationToken);
        if (saga?.SignedArtifactId is null)
        {
            // Kein signierter Vorgang (oder Saga-Zeile bereits archiviert) — kein Löschauftrag.
            return;
        }

        var artefaktIds = saga.SignedArtifactId.Value == saga.ArtifactId
            ? new List<Guid> { saga.ArtifactId }
            : new List<Guid> { saga.ArtifactId, saga.SignedArtifactId.Value };

        var gelöscht = await blobStore.DeleteAsync(artefaktIds, cancellationToken);
        if (gelöscht == 0)
        {
            // Bereits gelöscht (früherer Lauf / Neustart) — kein zweiter Audit-Eintrag.
            return;
        }

        // Löschungen sind vorgangsrelevante Ereignisse (REQ-18) und bleiben als
        // Metadaten bestehen, nachdem der Inhalt gegangen ist (REQ-19).
        await auditTrail.AppendAsync(
            jobId,
            AuditCategories.Deletion,
            $"Retention: Original- und Signaturdatei nach {options.Value.BlobRetentionDays} Tagen gelöscht",
            "system:retention",
            detail: null,
            cancellationToken);

        logger.LogInformation(
            "Blob-Retention: JobId {JobId} — {Deleted} Artefakt-Zeile(n) gelöscht (Frist {RetentionDays} Tage)",
            jobId, gelöscht, options.Value.BlobRetentionDays);
    }

    private async Task LöscheAbgelaufeneAuditEintraegeAsync(CancellationToken cancellationToken)
    {
        var stichtag = timeProvider.GetUtcNow().AddDays(-options.Value.AuditRetentionDays);

        // Vorprüfung: idempotente Läufe (zweiter Aufruf mit identischem Stichtag)
        // machen keine Arbeit.
        var fällige = await auditRetentionStore.CountExpiredAsync(stichtag, cancellationToken);
        if (fällige == 0)
        {
            return;
        }

        var ergebnis = await auditRetentionStore.DeleteOldestBlockAsync(stichtag, cancellationToken);
        if (ergebnis.DeletedCount == 0)
        {
            // Vorprüfung traf einen Eintrag, der beim Löschen bereits entfernt
            // wurde (paralleler Lauf / Neustart) — kein Audit-Eintrag, kein
            // Checkpoint.
            return;
        }

        // Sanctioned Lösch-Grenze festhalten, damit die Hash-Ketten-Prüfung
        // beim Admin-Abruf den nun fehlenden Vorgänger des ersten verbleibenden
        // Eintrags als bekannt anerkennt (REQ-18, AK-07, AK-18).
        var checkpoint = new AuditChainCheckpoint
        {
            SetAt = timeProvider.GetUtcNow(),
            LastDeletedEntryHash = ergebnis.LastDeletedEntryHash,
            FirstRemainingEntryId = ergebnis.FirstRemainingEntryId,
            DeletedCount = ergebnis.DeletedCount,
            Aktor = "system:retention",
            Reason = $"audit-retention-{options.Value.AuditRetentionDays}d",
        };
        await auditRetentionStore.AddCheckpointAsync(checkpoint, cancellationToken);

        // Löschung selbst auditprotokollieren (REQ-18, REQ-19). JobId =
        // Guid.Empty als Sentinel: das Ereignis ist systemweit, nicht
        // vorgangsbezogen; die Admin-UI kann es als System-Eintrag vom
        // Vorgangs-Audit abgrenzen.
        await auditTrail.AppendAsync(
            jobId: Guid.Empty,
            category: AuditCategories.Deletion,
            ereignis: $"Audit-Retention: {ergebnis.DeletedCount} Eintrag/Einträge älter als {options.Value.AuditRetentionDays} Tage gelöscht (Tabellenanfang bis Id {ergebnis.FirstRemainingEntryId - 1})",
            aktor: "system:retention",
            detail: $"{{\"deletedCount\":{ergebnis.DeletedCount},\"firstRemainingEntryId\":{ergebnis.FirstRemainingEntryId},\"retentionDays\":{options.Value.AuditRetentionDays}}}",
            cancellationToken);

        logger.LogInformation(
            "Audit-Retention: {Deleted} Audit-Eintrag/Einträge älter als {RetentionDays} Tage gelöscht (Checkpoint bei Id {FirstRemaining})",
            ergebnis.DeletedCount, options.Value.AuditRetentionDays, ergebnis.FirstRemainingEntryId);
    }
}
