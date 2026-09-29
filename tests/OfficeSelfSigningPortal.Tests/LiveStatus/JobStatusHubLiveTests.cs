using Microsoft.AspNetCore.Http.Connections;
using Microsoft.AspNetCore.SignalR;
using Microsoft.AspNetCore.SignalR.Client;
using Microsoft.AspNetCore.TestHost;
using OfficeSelfSigningPortal.Tests.Review;
using OfficeSelfSigningPortal.Tests.Support;
using OfficeSelfSigningPortal.WebUI.Authentication.Testing;
using OfficeSelfSigningPortal.WebUI.LiveStatus;
using Ossp.Contracts;

namespace OfficeSelfSigningPortal.Tests.LiveStatus;

/// <summary>
/// Seam S1 für den Live-Status-Kanal (IF-03): SignalR-Hub über den TestServer
/// (LongPolling — Websockets unterstützt der In-Memory-Server des S1 nicht).
/// Deckt den automatisierten Slice von TC-40/AK-20 (zwei Betrachter, gleicher
/// Zustand) sowie AK-08 (Push der In-Portal-Benachrichtigung) und AK-09
/// (serverseitige Watch-Autorisierung, TM-17).
/// </summary>
[Trait("Category", "Integration")]
public sealed class JobStatusHubLiveTests : IClassFixture<LiveStatusS1Fixture>, IAsyncLifetime
{
    private readonly LiveStatusS1Fixture _fixture;
    private readonly List<HubConnection> _connections = [];

    public JobStatusHubLiveTests(LiveStatusS1Fixture fixture)
    {
        _fixture = fixture;
    }

    public Task InitializeAsync() => Task.CompletedTask;

    public async Task DisposeAsync()
    {
        foreach (var connection in _connections)
        {
            await connection.DisposeAsync();
        }
    }

    [Fact]
    public async Task Watch_ZweiBeobachter_Sehen_DieselbeZustandsaenderung()
    {
        // Arrange — TC-40/AK-20: ein Vorgang im Scan, beobachtet von Einreicher und Bearbeiter.
        var jobId = Guid.NewGuid();
        await _fixture.SeedSagaAsync(jobId, SagaStateNames.ScanLaeuft, "submitter-1", DateTimeOffset.UtcNow.AddMinutes(-3));

        var owner = await ConnectAsync("submitter-1", groups: "Einreicher");
        var editor = await ConnectAsync("bearbeiter-1", groups: "Bearbeiter");
        var ownerSeen = AwaitEvent(owner, SagaStateNames.Signiert);
        var editorSeen = AwaitEvent(editor, SagaStateNames.Signiert);
        await owner.InvokeAsync(JobStatusHub.WatchJobMethodName, jobId);
        await editor.InvokeAsync(JobStatusHub.WatchJobMethodName, jobId);

        // Act — Zustandsübergang direkt im Saga-Store (in Produktion: WorkerService-Saga).
        var signedArtifactId = Guid.NewGuid();
        await _fixture.UpdateSagaStateAsync(jobId, SagaStateNames.Signiert, signedArtifactId);

        // Assert: beide Betrachter erhalten dieselbe Änderung inkl. Signatur-Referenz.
        var ownerEvent = await ownerSeen.Task.WaitAsync(TimeSpan.FromSeconds(30));
        var editorEvent = await editorSeen.Task.WaitAsync(TimeSpan.FromSeconds(30));
        Assert.Equal(jobId, ownerEvent.JobId);
        Assert.Equal(SagaStateNames.Signiert, ownerEvent.Status);
        Assert.Equal(SagaStateNames.Signiert, editorEvent.Status);
        Assert.Equal(signedArtifactId, ownerEvent.SignedArtifactId);
        Assert.Equal(signedArtifactId, editorEvent.SignedArtifactId);
    }

    [Fact]
    public async Task Watch_Endzustand_PushedInPortalBenachrichtigungAnEinreicher()
    {
        // Arrange — AK-08: Einreicher beobachtet Vorgang und seinen Benachrichtigungskanal.
        var jobId = Guid.NewGuid();
        await _fixture.SeedSagaAsync(jobId, SagaStateNames.ScanLaeuft, "submitter-1", DateTimeOffset.UtcNow.AddMinutes(-1));

        var owner = await ConnectAsync("submitter-1", groups: "Einreicher");
        var notificationSeen = new TaskCompletionSource<VorgangNotificationEvent>(TaskCreationOptions.RunContinuationsAsynchronously);
        owner.On<VorgangNotificationEvent>(JobStatusHub.VorgangNotificationMethod, e =>
        {
            notificationSeen.TrySetResult(e);
            return Task.CompletedTask;
        });
        await owner.InvokeAsync(JobStatusHub.WatchJobMethodName, jobId);
        await owner.InvokeAsync(JobStatusHub.WatchNotificationsMethodName);

        // Act — Vorgang wird abgelehnt (Endzustand).
        await _fixture.UpdateSagaStateAsync(jobId, SagaStateNames.Abgelehnt);

        // Assert
        var notification = await notificationSeen.Task.WaitAsync(TimeSpan.FromSeconds(30));
        Assert.Equal(jobId, notification.JobId);
        Assert.Equal(SagaStateNames.Abgelehnt, notification.State);
        Assert.Equal("test.xlsm", notification.OriginalFileName);
    }

    [Fact]
    public async Task Watch_Rueckfrage_PushedBenachrichtigung()
    {
        // Arrange — AK-08 nennt ausdrücklich Rückfragen als benachrichtigungsrelevant.
        var jobId = Guid.NewGuid();
        await _fixture.SeedSagaAsync(jobId, SagaStateNames.ReviewAusstehend, "submitter-1", DateTimeOffset.UtcNow.AddMinutes(-10));

        var owner = await ConnectAsync("submitter-1", groups: "Einreicher");
        var seen = new TaskCompletionSource<VorgangNotificationEvent>(TaskCreationOptions.RunContinuationsAsynchronously);
        owner.On<VorgangNotificationEvent>(JobStatusHub.VorgangNotificationMethod, e =>
        {
            if (e.State == SagaStateNames.RueckfrageAusstehend)
            {
                seen.TrySetResult(e);
            }

            return Task.CompletedTask;
        });
        await owner.InvokeAsync(JobStatusHub.WatchJobMethodName, jobId);
        await owner.InvokeAsync(JobStatusHub.WatchNotificationsMethodName);

        // Act
        await _fixture.UpdateSagaStateAsync(jobId, SagaStateNames.RueckfrageAusstehend);

        // Assert
        var notification = await seen.Task.WaitAsync(TimeSpan.FromSeconds(30));
        Assert.Equal(jobId, notification.JobId);
    }

    [Fact]
    public async Task WatchDashboard_NachEntscheidung_WirdAktualisierteListeGepusht()
    {
        // Arrange — AK-06: Dashboard beobachtet offene Reviews; nach Entscheidung (hier:
        // Übergang aus dem Review heraus) muss die Liste live aktualisiert werden.
        var jobId = Guid.NewGuid();
        await _fixture.SeedSagaAsync(jobId, SagaStateNames.ReviewAusstehend, "submitter-1", DateTimeOffset.UtcNow.AddMinutes(-15));

        var editor = await ConnectAsync("bearbeiter-1", groups: "Bearbeiter");
        var received = new List<int>();
        var pushed = new TaskCompletionSource<OpenReviewsChangedEvent>(TaskCreationOptions.RunContinuationsAsynchronously);
        editor.On<OpenReviewsChangedEvent>(JobStatusHub.OpenReviewsChangedMethod, e =>
        {
            lock (received)
            {
                received.Add(e.Reviews.Count);
            }

            // Erst die Aktualisierung (leere Liste) melden, nicht der initiale Stand.
            if (e.Reviews.Count == 0)
            {
                pushed.TrySetResult(e);
            }

            return Task.CompletedTask;
        });
        await editor.InvokeAsync(JobStatusHub.WatchDashboardMethodName);

        // Act — Vorgang verlässt den Review-Pfad.
        await _fixture.UpdateSagaStateAsync(jobId, SagaStateNames.SignierungAngefragt);

        // Assert
        var update = await pushed.Task.WaitAsync(TimeSpan.FromSeconds(30));
        Assert.Empty(update.Reviews);
    }

    [Fact]
    public async Task Watch_FremderVorgang_WirdVomHubAbgelehnt()
    {
        // Arrange — TM-17/AK-09: ein fremder Einreicher darf den Vorgang nicht beobachten.
        var jobId = Guid.NewGuid();
        await _fixture.SeedSagaAsync(jobId, SagaStateNames.ScanLaeuft, "submitter-1", DateTimeOffset.UtcNow);

        var stranger = await ConnectAsync("submitter-2", groups: "Einreicher");

        // Act + Assert
        await Assert.ThrowsAsync<HubException>(
            () => stranger.InvokeAsync(JobStatusHub.WatchJobMethodName, jobId));
    }

    [Fact]
    public async Task WatchDashboard_ohneBearbeiterRolle_WirdVomHubAbgelehnt()
    {
        // Arrange — AK-09: Dashboard-Watch erfordert die Bearbeiter-Rolle (serverseitig).
        var submitter = await ConnectAsync("submitter-1", groups: "Einreicher");

        // Act + Assert
        await Assert.ThrowsAsync<HubException>(
            () => submitter.InvokeAsync(JobStatusHub.WatchDashboardMethodName));
    }

    private TaskCompletionSource<JobStatusChangedEvent> AwaitEvent(HubConnection connection, string expectedState)
    {
        var seen = new TaskCompletionSource<JobStatusChangedEvent>(TaskCreationOptions.RunContinuationsAsynchronously);
        connection.On<JobStatusChangedEvent>(JobStatusHub.JobStatusChangedMethod, e =>
        {
            // Erst die erwartete Änderung melden — WatchJob pusht den Ausgangszustand
            // sofort an den Aufrufer (Initial-Sync), der hier ignoriert wird.
            if (e.Status == expectedState)
            {
                seen.TrySetResult(e);
            }

            return Task.CompletedTask;
        });
        return seen;
    }

    private async Task<HubConnection> ConnectAsync(string user, string groups)
    {
        // TestServer-Handler + Fake-IdP-Header: Der Seam S1 testet denselben Hub wie
        // die Produktiv-Verdrahtung (kein Ersatz der AuthN/AuthZ-Infrastruktur).
        var handler = ((TestServer)_fixture.Factory.Server).CreateHandler();
        var connection = new HubConnectionBuilder()
            .WithUrl(new Uri(_fixture.Factory.Server.BaseAddress, JobStatusHub.Route), options =>
            {
                options.HttpMessageHandlerFactory = _ => handler;
                options.Transports = HttpTransportType.LongPolling;
                options.Headers.Add(TestAuthHandler.UserHeader, user);
                options.Headers.Add(TestAuthHandler.GroupsHeader, groups);
            })
            .WithAutomaticReconnect()
            .Build();
        await connection.StartAsync();
        _connections.Add(connection);
        return connection;
    }
}

/// <summary>
/// Seam-S1-Variante mit kurzem Pollintervall: der Status-Wächter soll Zustands-
/// änderungen schnell bemerken, ohne die Tests auf Wartezeiten zu zwingen.
/// </summary>
public sealed class LiveStatusS1Fixture : ReviewS1Fixture
{
    protected override IReadOnlyDictionary<string, string>? ExtraSettings =>
        new Dictionary<string, string>
        {
            [$"{LiveStatusOptions.SectionName}:{nameof(LiveStatusOptions.PollIntervalSeconds)}"] = "1",
        };
}
