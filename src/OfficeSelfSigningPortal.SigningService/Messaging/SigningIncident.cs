using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using OfficeSelfSigningPortal.SigningService.Data;

namespace OfficeSelfSigningPortal.SigningService.Messaging;

/// <summary>
/// Vorfall-Protokoll des SigningService (AK-39: Guard-Ablehnungen werden auditiert).
/// Ticket 06 konsolidiert die Vorfalls-Tabelle in den append-only, hash-verketteten
/// Audit-Trail; Tabelle und Schreibpfad bleiben bewusst minimal.
/// </summary>
public sealed class SigningIncident
{
    public long Id { get; set; }
    public Guid JobId { get; set; }
    public DateTimeOffset OccurredAt { get; set; }
    public string Reason { get; set; } = string.Empty;
}

public interface ISigningIncidentWriter
{
    Task RecordAsync(Guid jobId, string reason, CancellationToken cancellationToken);
}

/// <summary>EF-Core-Basis über <see cref="IDbContextFactory{SigningDbContext}"/> (synchroner Consumer).</summary>
public sealed class EfSigningIncidentWriter(
    IDbContextFactory<SigningDbContext> contextFactory,
    ILogger<EfSigningIncidentWriter> logger) : ISigningIncidentWriter
{
    public async Task RecordAsync(Guid jobId, string reason, CancellationToken cancellationToken)
    {
        try
        {
            await using var db = await contextFactory.CreateDbContextAsync(cancellationToken);
            db.SigningIncidents.Add(new SigningIncident
            {
                JobId = jobId,
                OccurredAt = DateTimeOffset.UtcNow,
                Reason = reason,
            });
            await db.SaveChangesAsync(cancellationToken);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // Best-effort: Ein Protokoll-Fehlversuch darf die Ablehnung nicht kippen.
            logger.LogError(ex, "Vorfall für JobId {JobId} konnte nicht protokolliert werden", jobId);
        }
    }
}
