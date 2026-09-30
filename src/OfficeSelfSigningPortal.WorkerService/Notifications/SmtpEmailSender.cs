using MailKit.Security;
using MimeKit;
using Microsoft.Extensions.Options;

namespace OfficeSelfSigningPortal.WorkerService.Notifications;

/// <summary>
/// Aktiver Pfad (SMTP konfiguriert): Versand über MailKit — der TLS-Modus ist
/// erzwungen und nicht abschaltbar (TLS-Zwang, TM-11): Port 465 = implizites TLS,
/// sonst STARTTLS (Upgrade wird verlangt; ein Server ohne STARTTLS wird abgelehnt).
/// Der Client wird pro Sendung neu erstellt (kein geteilter Zustand, kein Pooling).
/// </summary>
public sealed class SmtpEmailSender : IEmailSender
{
    private const int ImplicitTlsPort = 465;

    private readonly SmtpOptions _options;

    public SmtpEmailSender(IOptions<SmtpOptions> options)
    {
        _options = options.Value;
    }

    public SmtpEmailSender(SmtpOptions options)
    {
        _options = options;
    }

    public async Task SendAsync(string to, string subject, string body, CancellationToken cancellationToken)
    {
        using var client = CreateClient();
        await client.ConnectAsync(_options.Host!, _options.Port, ResolveSecureSocketOptions(), cancellationToken);

        if (!string.IsNullOrEmpty(_options.UserName))
        {
            await client.AuthenticateAsync(_options.UserName, _options.Password ?? string.Empty, cancellationToken);
        }

        var message = new MimeMessage();
        message.From.Add(MailboxAddress.Parse(_options.From));
        message.To.Add(MailboxAddress.Parse(to));
        message.Subject = subject;
        message.Body = new TextPart("plain") { Text = body };
        await client.SendAsync(message, cancellationToken);
        await client.DisconnectAsync(quit: true, cancellationToken);
    }

    /// <summary>
    /// Baut den Client (Zertifikats-Callback nur mit explizitem Dev-Flag). Intern
    /// für den Unit-Seam (TLS-Zwang-Verifikation, TM-11).
    /// </summary>
    internal MailKit.Net.Smtp.SmtpClient CreateClient()
    {
        if (string.IsNullOrWhiteSpace(_options.Host))
        {
            throw new InvalidOperationException(
                "SmtpEmailSender erfordert Smtp:Host — ohne Host ist der E-Mail-Pfad deaktiviert (NullEmailSender, AK-21).");
        }

        if (string.IsNullOrWhiteSpace(_options.From))
        {
            throw new InvalidOperationException(
                "Smtp:From fehlt — ohne Absenderadresse wäre der E-Mail-Pfad halb konfiguriert.");
        }

        var client = new MailKit.Net.Smtp.SmtpClient();
        if (_options.DisableCertificateValidation)
        {
            // Dev-Only (lokaler MailPit, selbstsigniert) — siehe SmtpOptions.DisableCertificateValidation.
            client.ServerCertificateValidationCallback = static (_, _, _, _) => true;
        }

        return client;
    }

    /// <summary>
    /// Erzwungener TLS-Modus (TM-11): implizites TLS auf 465, sonst STARTTLS-Pflicht.
    /// Intern für den Unit-Seam.
    /// </summary>
    internal SecureSocketOptions ResolveSecureSocketOptions()
        => _options.Port == ImplicitTlsPort
            ? SecureSocketOptions.SslOnConnect
            : SecureSocketOptions.StartTls;
}
