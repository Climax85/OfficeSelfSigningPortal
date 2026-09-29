using System.Security.Cryptography;
using MassTransit;
using OfficeSelfSigningPortal.SigningService.Data;
using OfficeSelfSigningPortal.SigningService.Messaging;
using Ossp.Audit;
using Ossp.Contracts;

namespace OfficeSelfSigningPortal.SigningService.Signing;

/// <summary>
/// Signier-Pipeline der Sign-Queue (Ticket 08, hinter dem Saga-Guard): verifiziert den
/// persistierten Saga-Status (Defense-in-Depth, TM-19), prüft <see cref="SignMacroRequested.ContentSha256"/>
/// gegen den Blob VOR jeder Signatur (TOCTOU, AK-52, TC-29, TM-03), signiert via
/// <see cref="IVbaProjectSigner"/> mit dem Zertifikat aus <see cref="ICodeSigningKeyProvider"/>
/// (REQ-15) und legt den signierten Blob als neue Artefakt-Zeile ab. Erfolg →
/// <see cref="SignMacroCompleted"/>; fachlicher Fehler → <see cref="SignMacroFailed"/>
/// (Retryable=false → Saga: Fehler + Alarm). Transiente Fehler (Blob kurzzeitig nicht
/// lesbar, Vault via Polly) → Retryable=true + Exception an MassTransit (Redelivery-Puffer,
/// nach Limit Fault-Queue — kein Request-Verlust, AK-55/TC-34, REQ-22).
/// </summary>
public sealed class SignMacroSigningConsumer(
    ISagaStateReader sagaStateReader,
    IArtifactBlobAccess artifactBlobs,
    ICodeSigningKeyProvider keyProvider,
    IVbaProjectSigner signer,
    IAuditTrailWriter auditTrail,
    ILogger<SignMacroSigningConsumer> logger) : IConsumer<SignMacroRequested>
{
    public async Task Consume(ConsumeContext<SignMacroRequested> context)
    {
        var message = context.Message;

        // Defense-in-Depth (TM-19): Der Guard (AK-39) ist das auditierte Vordertor; die
        // Pipeline verifiziert den Status erneut, bevor ein Key materialisiert wird.
        var state = await sagaStateReader.GetSagaStateAsync(message.JobId, context.CancellationToken);
        if (!string.Equals(state, SagaStateNames.SignierungAngefragt, StringComparison.Ordinal))
        {
            logger.LogWarning(
                "Signierauftrag {JobId} übersprungen: Saga-Status {State} — Ablehnung erfolgt durch den Guard",
                message.JobId,
                state ?? "<keine Saga>");
            return;
        }

        var blob = await artifactBlobs.ReadAsync(message.ArtifactId, context.CancellationToken);
        if (blob is null)
        {
            // Transiente Inkonsistenz: Blob committet vor Saga-Wechsel — puffern statt ablehnen.
            await PublishFailureAsync(context, message, "Artefakt-Blob nicht lesbar", Retryable: true);
            throw new InvalidOperationException(
                $"Artefakt-Blob {message.ArtifactId} für JobId {message.JobId} nicht gefunden — Redelivery.");
        }

        // TOCTOU-Verifizierung vor jeder Signatur (AK-52, TC-29, TM-03): Der Blob muss
        // exakt der Datei entsprechen, die gescannt wurde.
        var blobSha256 = Convert.ToHexString(SHA256.HashData(blob.Content));
        if (!string.Equals(blobSha256, message.ContentSha256, StringComparison.OrdinalIgnoreCase))
        {
            logger.LogError(
                "TOCTOU-Verletzung bei JobId {JobId}: Blob-Hash {BlobHash} weicht vom Auftrags-Hash {RequestHash} ab — keine Signatur, Alarm",
                message.JobId,
                blobSha256,
                message.ContentSha256);

            await auditTrail.AppendAsync(
                message.JobId,
                AuditCategories.Guard,
                "Signierauftrag abgelehnt: ContentSha256 weicht vom Blob ab (TOCTOU)",
                "system:signing-pipeline",
                detail: $"{{\"blobSha256\":\"{blobSha256}\",\"requestSha256\":\"{message.ContentSha256}\"}}",
                context.CancellationToken);

            await PublishFailureAsync(context, message, "ContentSha256-Verifizierung fehlgeschlagen (TOCTOU)", Retryable: false);
            return;
        }

        using var certificate = await keyProvider.GetSigningCertificateAsync(context.CancellationToken);

        using var document = new MemoryStream();
        await document.WriteAsync(blob.Content, context.CancellationToken);
        document.Position = 0;

        var result = await signer.SignAsync(document, certificate, context.CancellationToken);
        if (!result.Success)
        {
            // Fachlicher Signaturfehler (z. B. VBA-Projekt nicht Office-konform) — ein
            // erneuter Versuch ändert nichts: nicht retryable (Anhang A, TC-29).
            logger.LogError(
                "Signierung fehlgeschlagen für JobId {JobId}: {ErrorCode} — keine Signatur, Alarm",
                message.JobId,
                result.ErrorCode);
            await PublishFailureAsync(
                context, message, $"Signierung fehlgeschlagen ({result.ErrorCode})", Retryable: false);
            return;
        }

        var signedArtifactId = Guid.NewGuid();
        var signedSha256 = await artifactBlobs.StoreSignedAsync(signedArtifactId, document.ToArray(), context.CancellationToken);

        // Signier-Evidenz in den konsolidierten Audit-Trail (REQ-18, TM-08 inkl. Auto-Signing:
        // RequestedBy system:auto-sign bleibt am Auftrag nachvollziehbar).
        await auditTrail.AppendAsync(
            message.JobId,
            AuditCategories.Signing,
            "Signierung abgeschlossen (V3, SHA-256)",
            "system:signing-pipeline",
            detail: $"{{\"signedArtifactId\":\"{signedArtifactId}\",\"signedSha256\":\"{signedSha256}\"," +
                    $"\"requestedBy\":\"{message.RequestedBy}\",\"certificateThumbprint\":\"{certificate.Thumbprint}\"}}",
            context.CancellationToken);

        await context.Publish(new SignMacroCompleted(
            message.JobId,
            signedArtifactId,
            DateTimeOffset.UtcNow));
    }

    private static async Task PublishFailureAsync(
        ConsumeContext<SignMacroRequested> context,
        SignMacroRequested message,
        string reason,
        bool Retryable)
        => await context.Publish(new SignMacroFailed(message.JobId, reason, Retryable));
}
