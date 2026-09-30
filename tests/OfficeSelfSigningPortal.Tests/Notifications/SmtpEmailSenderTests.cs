using MailKit.Security;
using Microsoft.Extensions.Options;
using OfficeSelfSigningPortal.WorkerService.Notifications;
using Xunit;

namespace OfficeSelfSigningPortal.Tests.Notifications;

/// <summary>
/// SmtpEmailSender (Ticket 10): Konfigurations-Validierung beim Start und
/// TLS-Zwang (TM-11) — der sichere Modus ist erzwungen (465 = implizites TLS,
/// sonst STARTTLS-Pflicht), die Zertifikatsprüfung darf nur per explizitem
/// Dev-Flag (lokaler MailPit, selbstsigniert) ausgesetzt werden. Ohne Smtp:Host
/// ist der Versandpfad deaktiviert (AK-21), niemals halb-konfiguriert.
/// </summary>
public sealed class SmtpEmailSenderTests
{
    private static SmtpOptions GueltigeOptions() => new()
    {
        Host = "smtp.example.org",
        Port = 587,
        From = "portal@example.org",
    };

    [Fact]
    public void Konstruktor_ohneHost_wirftKlareFehlermeldung()
    {
        // Arrange
        var options = GueltigeOptions();
        options.Host = null;

        // Act / Assert
        var ex = Assert.Throws<InvalidOperationException>(
            () => new SmtpEmailSender(Options.Create(options)).CreateClient());
        Assert.Contains("Smtp:Host", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void CreateClient_ohneFrom_wirftKlareFehlermeldung()
    {
        // Arrange: Versand ohne Absenderadresse wäre halb-konfiguriert — harter Startfehler.
        var options = GueltigeOptions();
        options.From = null;

        // Act / Assert
        var ex = Assert.Throws<InvalidOperationException>(
            () => new SmtpEmailSender(Options.Create(options)).CreateClient());
        Assert.Contains("Smtp:From", ex.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(587, SecureSocketOptions.StartTls)]
    [InlineData(2525, SecureSocketOptions.StartTls)]
    [InlineData(465, SecureSocketOptions.SslOnConnect)]
    public void ResolveSecureSocketOptions_erzwingtTlsFuerJedenPort(int port, SecureSocketOptions erwartet)
    {
        // Arrange (TM-11: TLS-Zwang — kein Plaintext-Modus existiert).
        var options = GueltigeOptions();
        options.Port = port;

        // Act
        var sender = new SmtpEmailSender(Options.Create(options));

        // Assert
        Assert.Equal(erwartet, sender.ResolveSecureSocketOptions());
    }

    [Fact]
    public void CreateClient_mitDevFlag_setztZertifikatsCallback()
    {
        // Arrange: DisableCertificateValidation ist das ausschließlich für den
        // lokalen MailPit-Container (selbstsigniert) vorgesehene Dev-Flag.
        var options = GueltigeOptions();
        options.DisableCertificateValidation = true;

        // Act
        var sender = new SmtpEmailSender(Options.Create(options));
        using var client = sender.CreateClient();

        // Assert
        Assert.NotNull(client.ServerCertificateValidationCallback);
    }

    [Fact]
    public void CreateClient_ohneDevFlag_prueftZertifikatStandardmaessig()
    {
        // Arrange (TM-11: Produktionspfad — keine Callback-Ausnahme).
        var options = GueltigeOptions();

        // Act
        var sender = new SmtpEmailSender(Options.Create(options));
        using var client = sender.CreateClient();

        // Assert
        Assert.Null(client.ServerCertificateValidationCallback);
    }
}
