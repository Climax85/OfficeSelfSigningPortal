using MassTransit;
using Ossp.Audit;
using Ossp.Contracts;

namespace OfficeSelfSigningPortal.SigningService.Messaging;

/// <summary>
/// Guard-Consumer der Sign-Queue (TM-19, AK-39, TC-30, REQ-14): Ein
/// <see cref="SignMacroRequested"/> wird nur dann akzeptiert, wenn der persistierte
/// Saga-Status des Vorgangs <c>SignierungAngefragt</c> ist — unabhängig davon, was
/// die Nachricht selbst behauptet. Andernfalls: Ablehnung, keine Signatur,
/// Audit-Eintrag (konsolidierter Audit-Trail, Ticket 06) plus
/// <see cref="JobFailed"/> (Stage "signing", nicht retryable). Die eigentliche
/// Signier-Pipeline (VbaProjectSigner, ContentSha256-Verifizierung gegen den Blob)
/// liefert Ticket 08; dieser Guard ist ihr unverrückbarer Vordertor.
/// </summary>
public sealed class SignMacroRequestGuardConsumer(
    ISagaStateReader sagaStateReader,
    IAuditTrailWriter auditTrail,
    ILogger<SignMacroRequestGuardConsumer> logger) : IConsumer<SignMacroRequested>
{
    public async Task Consume(ConsumeContext<SignMacroRequested> context)
    {
        var message = context.Message;

        var state = await sagaStateReader.GetSagaStateAsync(message.JobId, context.CancellationToken);

        if (!string.Equals(state, SagaStateNames.SignierungAngefragt, StringComparison.Ordinal))
        {
            logger.LogWarning(
                "SignMacroRequested für JobId {JobId} abgelehnt: Saga-Status {State} — möglicher Fremd-Publish auf der Sign-Queue",
                message.JobId,
                state ?? "<keine Saga>");

            // Ablehnung ist sicherheitsrelevant (AK-39) und gehört in den Audit-Trail.
            // Best-effort: Ein Protokoll-Fehlversuch darf die Ablehnung selbst nicht kippen.
            try
            {
                await auditTrail.AppendAsync(
                    message.JobId,
                    AuditCategories.Guard,
                    $"SignMacroRequested abgelehnt: Saga-Status {(state ?? "<keine Saga>")}",
                    "system:signing-guard",
                    detail: null,
                    context.CancellationToken);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                logger.LogError(ex, "Guard-Ablehnung für JobId {JobId} konnte nicht auditiert werden", message.JobId);
            }

            await context.Publish(new JobFailed(
                message.JobId,
                "signing",
                "SignMacroRequested ohne Saga-Status SignierungAngefragt — abgelehnt",
                Retryable: false,
                DateTimeOffset.UtcNow));

            return;
        }

        logger.LogInformation(
            "SignMacroRequested für JobId {JobId} verifiziert (Status SignierungAngefragt) — Übergabe an die Signier-Pipeline (Ticket 08)",
            message.JobId);
    }
}
