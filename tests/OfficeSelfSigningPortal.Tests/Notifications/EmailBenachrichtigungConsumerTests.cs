using MassTransit;
using MassTransit.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using OfficeSelfSigningPortal.WorkerService.Messaging;
using OfficeSelfSigningPortal.WorkerService.Notifications;
using OfficeSelfSigningPortal.WorkerService.Saga;
using Ossp.Contracts;
using Xunit;

namespace OfficeSelfSigningPortal.Tests.Notifications;

/// <summary>
/// Seam S2 (Consumer-Ebene, Ticket 10): E-Mail-Benachrichtigungen aus der Saga —
/// TC-41 (E-Mail enthält nur Status und Link, keine Inhalte/Anhänge), TM-02/TM-11,
/// REQ-08. Versand an den Einreicher (SubmitterEmail aus ScanRequested) und — beim
/// Malicious-Pfad — zusätzlich an die konfigurierte Security-Team-Adresse (REQ-13).
/// Ohne SMTP-Konfiguration schluckt der NullEmailSender alle Versände still
/// (AK-21, TC-42: kein Fehler, keine Blockade).
/// </summary>
public sealed class EmailBenachrichtigungConsumerTests : IAsyncLifetime
{
    private static readonly OsspRetryOptions TestRetry = new()
    {
        Limit = 2,
        MinDelay = TimeSpan.FromMilliseconds(20),
        MaxDelay = TimeSpan.FromMilliseconds(60),
    };

    private ServiceProvider _provider = null!;
    private ITestHarness _harness = null!;
    private FakeEmailSender _sender = null!;

    public async Task InitializeAsync()
    {
        _sender = new FakeEmailSender();

        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton<IEmailSender>(_sender);
        services.AddSingleton<IOptions<NotificationOptions>>(_ =>
            Options.Create(new NotificationOptions
            {
                PortalBaseUrl = "https://portal.example.org",
                SecurityTeamAddress = "security-team@example.org",
            }));
        services.AddMassTransitTestHarness(x =>
        {
            x.AddConsumer<EmailBenachrichtigungConsumer>();
            x.UsingInMemory((context, cfg) =>
            {
                cfg.ReceiveEndpoint(QueueNames.EmailBenachrichtigung, e =>
                    AnalysisSagaBusConfiguration.ConfigureEmailNotificationEndpoint(e, context, TestRetry));
            });
        });

        _provider = services.BuildServiceProvider(true);
        _harness = _provider.GetRequiredService<ITestHarness>();
        await _harness.Start();
    }

    public async Task DisposeAsync()
    {
        await _harness.Stop();
        await _provider.DisposeAsync();
    }

    [Fact]
    public async Task Consume_MitEinreicherEmail_versendetNurStatusUndLink()
    {
        // Arrange (TC-41): Endzustand erreicht, Einreicher hat eine E-Mail-Adresse.
        var jobId = Guid.NewGuid();

        // Act
        await _harness.Bus.Publish(new BenachrichtigungAusgeloest(
            jobId, "Signiert", "submitter-1@example.org", SecurityTeam: false));

        // Assert: genau eine E-Mail an den Einreicher, Status und Link enthalten.
        Assert.True(await _harness.Consumed.Any<BenachrichtigungAusgeloest>());
        var email = Assert.Single(_sender.Sent);
        Assert.Equal("submitter-1@example.org", email.To);
        Assert.Contains("Signiert", email.Subject, StringComparison.Ordinal);

        // TC-41/TM-11: nur Status + Portal-Link — keine Dateiinhalte, Anhänge, Befunde.
        Assert.Contains("https://portal.example.org/vorgang/" + jobId, email.Body, StringComparison.Ordinal);
        Assert.Contains("Signiert", email.Body, StringComparison.Ordinal);
        Assert.DoesNotContain("doku.xlsm", email.Body, StringComparison.Ordinal);
        Assert.DoesNotContain("Score", email.Body, StringComparison.Ordinal);
        Assert.DoesNotContain("Finding", email.Body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Consume_SecurityTeamFlag_versendetZusaetzlichAnSecurityAdresse()
    {
        // Arrange (REQ-13, TM-02): Malicious-Pfad — Security-Team bekommt dieselbe
        // Status-Plus-Link-Mail (keine Befunddetails, kein Anhang).
        var jobId = Guid.NewGuid();

        // Act
        await _harness.Bus.Publish(new BenachrichtigungAusgeloest(
            jobId, "Abgelehnt", "submitter-1@example.org", SecurityTeam: true));

        // Assert: zwei Mails — Einreicher und Security-Team, beide ohne Inhalte.
        Assert.True(await _harness.Consumed.Any<BenachrichtigungAusgeloest>());
        Assert.Equal(2, _sender.Sent.Count);
        Assert.Contains(_sender.Sent, m => m.To == "security-team@example.org");
        Assert.All(_sender.Sent, m =>
        {
            Assert.Contains("Abgelehnt", m.Subject, StringComparison.Ordinal);
            Assert.Contains("https://portal.example.org/vorgang/" + jobId, m.Body, StringComparison.Ordinal);
            Assert.DoesNotContain("Macro", m.Body, StringComparison.OrdinalIgnoreCase);
        });
    }

    [Fact]
    public async Task Consume_SecurityTeamOhneKonfigurierteAdresse_versendetNurAnEinreicher()
    {
        // Arrange: Security-Team-Adresse nicht konfiguriert — kein Versand ins Leere.
        var services = new ServiceCollection();
        services.AddLogging();
        var sender = new FakeEmailSender();
        services.AddSingleton<IEmailSender>(sender);
        services.AddSingleton<IOptions<NotificationOptions>>(_ =>
            Options.Create(new NotificationOptions
            {
                PortalBaseUrl = "https://portal.example.org",
                SecurityTeamAddress = null,
            }));
        services.AddMassTransitTestHarness(x =>
        {
            x.AddConsumer<EmailBenachrichtigungConsumer>();
            x.UsingInMemory((context, cfg) =>
            {
                cfg.ReceiveEndpoint(QueueNames.EmailBenachrichtigung, e =>
                    AnalysisSagaBusConfiguration.ConfigureEmailNotificationEndpoint(e, context, TestRetry));
            });
        });
        await using var provider = services.BuildServiceProvider(true);
        var harness = provider.GetRequiredService<ITestHarness>();
        await harness.Start();

        // Act
        await harness.Bus.Publish(new BenachrichtigungAusgeloest(
            Guid.NewGuid(), "Abgelehnt", "submitter-1@example.org", SecurityTeam: true));

        // Assert
        Assert.True(await harness.Consumed.Any<BenachrichtigungAusgeloest>());
        var email = Assert.Single(sender.Sent);
        Assert.Equal("submitter-1@example.org", email.To);
        await harness.Stop();
    }

    [Fact]
    public async Task Consume_OhneEinreicherEmailUndOhneSecurityTeam_versendetNichts()
    {
        // Arrange: IdP liefert keinen E-Mail-Claim — keine Adresse, kein Versand,
        // aber auch kein Fehler (REQ-08: Benachrichtigung nur falls möglich).
        var jobId = Guid.NewGuid();

        // Act
        await _harness.Bus.Publish(new BenachrichtigungAusgeloest(
            jobId, "Fehler", SubmitterEmail: null, SecurityTeam: false));

        // Assert
        Assert.True(await _harness.Consumed.Any<BenachrichtigungAusgeloest>());
        Assert.Empty(_sender.Sent);
    }

    [Fact]
    public async Task Consume_ohneSmtpKonfiguration_schlucktNullEmailSenderOhneFehler()
    {
        // Arrange (AK-21, TC-42): kein Smtp:Host — NullEmailSender ist aktiver Pfad.
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton<IEmailSender, NullEmailSender>();
        services.AddSingleton<IOptions<NotificationOptions>>(_ =>
            Options.Create(new NotificationOptions { PortalBaseUrl = "https://portal.example.org" }));
        services.AddMassTransitTestHarness(x =>
        {
            x.AddConsumer<EmailBenachrichtigungConsumer>();
            x.UsingInMemory((context, cfg) =>
            {
                cfg.ReceiveEndpoint(QueueNames.EmailBenachrichtigung, e =>
                    AnalysisSagaBusConfiguration.ConfigureEmailNotificationEndpoint(e, context, TestRetry));
            });
        });
        await using var provider = services.BuildServiceProvider(true);
        var harness = provider.GetRequiredService<ITestHarness>();
        await harness.Start();

        // Act
        await harness.Bus.Publish(new BenachrichtigungAusgeloest(
            Guid.NewGuid(), "Signiert", "submitter-1@example.org", SecurityTeam: false));

        // Assert: konsumiert ohne Exception, kein Fault, kein Retry-Loop.
        Assert.True(await harness.Consumed.Any<BenachrichtigungAusgeloest>());
        Assert.False(await harness.Published.Any<Fault<BenachrichtigungAusgeloest>>());
        await harness.Stop();
    }

    /// <summary>Fängt alle Versände für Asserts ab — ersetzt den echten SMTP-Transport.</summary>
    private sealed class FakeEmailSender : IEmailSender
    {
        public List<(string To, string Subject, string Body)> Sent { get; } = [];

        public Task SendAsync(string to, string subject, string body, CancellationToken cancellationToken)
        {
            Sent.Add((to, subject, body));
            return Task.CompletedTask;
        }
    }
}
