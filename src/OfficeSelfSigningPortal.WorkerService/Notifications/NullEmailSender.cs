using Microsoft.Extensions.Logging;

namespace OfficeSelfSigningPortal.WorkerService.Notifications;

/// <summary>
/// Deaktivierter Pfad (kein Smtp:Host, AK-21/TC-42): schluckt Versände still —
/// kein Fehler, keine Blockade, keine halb konfigurierte SMTP-Verbindung.
/// </summary>
public sealed class NullEmailSender(ILogger<NullEmailSender> logger) : IEmailSender
{
    public Task SendAsync(string to, string subject, string body, CancellationToken cancellationToken)
    {
        logger.LogDebug("E-Mail-Pfad deaktiviert (kein Smtp:Host) — Versand an {To} übersprungen.", to);
        return Task.CompletedTask;
    }
}
