using MassTransit;
using OfficeSelfSigningPortal.WorkerService.Scanning;
using Ossp.Contracts;

namespace OfficeSelfSigningPortal.WorkerService.Messaging;

/// <summary>
/// Führt den Scanauftrag aus (Endpoint <c>ossp.scan-requested</c>, Ticket 05): liest den
/// Artefakt-Blob aus dem Ingestion-Speicher, verifiziert den TOCTOU-Hash (TM-03) und
/// verdichtet alle Engine-Stages über den <see cref="ScanOrchestrator"/> zu
/// <see cref="ScanCompleted"/> (Anhang A). Die Saga konsumiert das Ergebnis auf ihrem
/// eigenen Endpoint.
///
/// Fehlersemantik (REQ-22, TC-16): Fehlender Blob und Ausführungsfehler werfen —
/// MassTransit-Retry der Endpoint-Policy; nach dem Limit verschiebt der Broker die
/// Nachricht auf <c>ossp.scan-requested_error</c>, der Dead-Letter-Consumer meldet
/// <see cref="JobFailed"/> (Stage "scan") und die Saga führt den Vorgang auf Fehler.
/// </summary>
public sealed class ScanExecutionConsumer(
    IArtifactBlobStore blobStore,
    ScanOrchestrator orchestrator) : IConsumer<ScanRequested>
{
    public async Task Consume(ConsumeContext<ScanRequested> context)
    {
        var message = context.Message;

        var blob = await blobStore.ReadAsync(message.ArtifactId, context.CancellationToken);
        if (blob is null)
        {
            // Transienter Zustand (Replikations-/Commit-Verzögerung) — Retry greift.
            throw new InvalidOperationException(
                $"Artefakt {message.ArtifactId} für Vorgang {message.JobId} nicht gefunden.");
        }

        if (!string.Equals(blob.ContentSha256, message.ContentSha256, StringComparison.OrdinalIgnoreCase))
        {
            // TOCTOU-Verstoß (TM-03): Blob weicht vom vertraglichen Hash ab — kein Scan,
            // kein Retry (Retry liefert dasselbe Ergebnis).
            await context.Publish(new JobFailed(
                message.JobId,
                "scan",
                "ContentSha256-Mismatch: Blob weicht vom Scanauftrag ab",
                Retryable: false,
                DateTimeOffset.UtcNow));
            return;
        }

        var completed = await orchestrator.RunAsync(message, blob.Content, context.CancellationToken);
        await context.Publish(completed);
    }
}
