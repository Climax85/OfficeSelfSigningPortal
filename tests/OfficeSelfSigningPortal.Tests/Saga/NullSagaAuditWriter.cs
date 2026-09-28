using MassTransit;
using OfficeSelfSigningPortal.WorkerService.Saga;
using Ossp.Contracts;

namespace OfficeSelfSigningPortal.Tests.Saga;

/// <summary>Audit-No-Op für den InMemory-Seam S2 (Audit-Persistenz prüft der Transport-Slice).</summary>
public sealed class NullSagaAuditWriter : ISagaAuditWriter
{
    public Task WriteAsync(
        Guid jobId, string zustand, string ereignis, string aktor, string? detail, CancellationToken cancellationToken)
        => Task.CompletedTask;
}
