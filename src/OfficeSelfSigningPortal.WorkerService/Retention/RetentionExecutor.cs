using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using OfficeSelfSigningPortal.WorkerService.Data;
using Ossp.Audit;
using Ossp.Contracts;

namespace OfficeSelfSigningPortal.WorkerService.Retention;

/// <summary>
/// Fachliche Kernlogik des Retention-Jobs (Ticket 11, REQ-19, AK-19, TC-38):
/// Vorgänge, deren Signierung länger als die konfigurierbare Frist (Default 90 Tage)
/// zurückliegt, verlieren ihre Blob-Daten (Original + signierte Datei). Der
/// Signatur-Zeitstempel stammt aus dem Audit-Trail (jüngster Saga-Eintrag zum
/// Eintritt von <c>Signiert</c>) — dieselbe Basis wie das Download-Fenster der
/// WebUI (Verteidigung in der Tiefe). Der Audit-Bestand selbst ist append-only
/// und bleibt unverändert bestehen; jede Löschung wird als Audit-Eintrag
/// protokolliert (REQ-18) und über die gelöschte Zeilenzahl idempotent.
///
/// Läuft scoped im WorkerService (eigener DbContext-Zugriff auf worker- und
/// portal-DB); die Zeit kommt aus einem <see cref="TimeProvider"/> (fälschbar).
/// </summary>
public sealed class RetentionExecutor(
    WorkerDbContext workerDb,
    AuditDbContext auditDb,
    IRetentionBlobStore blobStore,
    IAuditTrailWriter auditTrail,
    IOptions<RetentionOptions> options,
    TimeProvider timeProvider,
    ILogger<RetentionExecutor> logger)
{
    public async Task ExecuteAsync(CancellationToken cancellationToken)
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
                logger.LogError(ex, "Retention-Löschung für JobId {JobId} fehlgeschlagen", jobId);
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
            "Retention: JobId {JobId} — {Deleted} Artefakt-Zeile(n) gelöscht (Frist {RetentionDays} Tage)",
            jobId, gelöscht, options.Value.BlobRetentionDays);
    }
}
