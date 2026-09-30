namespace OfficeSelfSigningPortal.WorkerService.Notifications;

/// <summary>Abstraktion des E-Mail-Transports — ersetzbar im Test, no-op ohne SMTP-Konfiguration.</summary>
public interface IEmailSender
{
    Task SendAsync(string to, string subject, string body, CancellationToken cancellationToken);
}
