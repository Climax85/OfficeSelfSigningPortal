using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using OfficeSelfSigningPortal.WorkerService.Data;

namespace OfficeSelfSigningPortal.WorkerService.Saga;

/// <summary>
/// EF-Core-Basis des <see cref="ISagaAuditWriter"/> über <see cref="IDbContextFactory{WorkerDbContext}"/>:
/// der State Machine steht ein synchroner Singleton zur Verfügung, die Einträge werden
/// in einem eigenen kurzen Kontext geschrieben. Atomarität mit der Saga-Zeile liefert
/// Ticket 06 (Hash-Kette über den Outbox-/Pipeline-Pfad).
/// </summary>
public sealed class EfSagaAuditWriter(
    IDbContextFactory<WorkerDbContext> contextFactory,
    ILogger<EfSagaAuditWriter> logger) : ISagaAuditWriter
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
            await using var db = await contextFactory.CreateDbContextAsync(cancellationToken);
            db.SagaAuditEntries.Add(new SagaAuditEntry
            {
                JobId = jobId,
                OccurredAt = DateTimeOffset.UtcNow,
                Zustand = zustand,
                Ereignis = ereignis,
                Aktor = aktor,
                Detail = detail,
            });
            await db.SaveChangesAsync(cancellationToken);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // Best-effort (siehe Interface-Doku): protokollieren, nicht propagieren.
            logger.LogError(ex, "Audit-Eintrag für JobId {JobId} ({Ereignis}) konnte nicht geschrieben werden", jobId, ereignis);
        }
    }
}
