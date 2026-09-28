using MassTransit;
using Microsoft.EntityFrameworkCore;
using OfficeSelfSigningPortal.WorkerService.Data;
using OfficeSelfSigningPortal.WorkerService.Saga;
using Ossp.Contracts;

namespace OfficeSelfSigningPortal.WorkerService.Messaging;

/// <summary>
/// Dead-Letter-Pfad des Scanner-Endpunkts (REQ-22, AK-22, TC-16): Eine wiederholt
/// fehlschlagende ScanRequested-Nachricht landet nach dem Retry-Limit in
/// <c>ossp.scan-requested_error</c>; dieser Consumer übernimmt sie fachlich und
/// meldet <see cref="JobFailed"/> (Stage "scan") — die Saga führt den Vorgang auf
/// <c>Fehler</c>. Der Scanner-Consumer selbst verdrahtet Ticket 05 und nutzt denselben
/// Endpoint-Namen/Retry-Policy, damit dieser Pfad ab dann produktiv greift.
/// </summary>
public sealed class ScanDeadLetterConsumer(ILogger<ScanDeadLetterConsumer> logger) : IConsumer<ScanRequested>
{
    public async Task Consume(ConsumeContext<ScanRequested> context)
    {
        logger.LogWarning(
            "Scanauftrag {JobId} nach Retry-Limit im DLQ — Vorgang wird auf Fehler gesetzt",
            context.Message.JobId);

        await context.Publish(new JobFailed(
            context.Message.JobId,
            "scan",
            "Retry-Limit überschritten — Auftrag aus der Error-Queue übernommen",
            Retryable: false,
            DateTimeOffset.UtcNow));
    }
}
