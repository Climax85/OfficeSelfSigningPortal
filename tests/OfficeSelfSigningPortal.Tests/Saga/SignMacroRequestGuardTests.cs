using MassTransit;
using MassTransit.Testing;
using Microsoft.Extensions.DependencyInjection;
using OfficeSelfSigningPortal.SigningService.Messaging;
using Ossp.Contracts;

namespace OfficeSelfSigningPortal.Tests.Saga;

/// <summary>
/// Guard der Sign-Queue (TM-19, AK-39, TC-30): SignMacroRequested ohne Saga-Status
/// SignierungAngefragt wird abgelehnt — keine Signatur, protokollierter Vorfall,
/// JobFailed(Stage "signing", nicht retryable).
/// </summary>
public sealed class SignMacroRequestGuardTests : IAsyncLifetime
{
    private ServiceProvider _provider = null!;
    private ITestHarness _harness = null!;
    private FakeSagaStateReader _stateReader = null!;
    private FakeSigningIncidentWriter _incidents = null!;

    public async Task InitializeAsync()
    {
        _stateReader = new FakeSagaStateReader();
        _incidents = new FakeSigningIncidentWriter();

        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton<ISagaStateReader>(_stateReader);
        services.AddSingleton<ISigningIncidentWriter>(_incidents);
        services.AddMassTransitTestHarness(x =>
        {
            x.AddSigningGuard();
            x.UsingInMemory((context, cfg) =>
            {
                cfg.ReceiveEndpoint(QueueNames.SignMacroRequested, e =>
                    SigningGuardBusConfiguration.ConfigureSigningGuardEndpoint(
                        e, context, retryLimit: 2, minDelay: TimeSpan.FromMilliseconds(20), maxDelay: TimeSpan.FromMilliseconds(60)));
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
    public async Task SignMacroRequested_ohne_SignierungAngefragt_wird_abgelehnt_ohne_Signatur()
    {
        // Arrange: Saga ist in ScanLaeuft — die Nachricht ist ein Fremd-Publish
        var jobId = Guid.NewGuid();
        _stateReader.State = SagaStateNames.ScanLaeuft;

        // Act
        await _harness.Bus.Publish(CreateSignMacroRequested(jobId));

        // Assert: Ablehnung als JobFailed, Vorfall protokolliert, keine weitere Aktivität
        Assert.True(await _harness.Published.Any<JobFailed>(m =>
            m.Context.Message.JobId == jobId
            && m.Context.Message.Stage == "signing"
            && !m.Context.Message.Retryable));
        Assert.Contains(_incidents.Recorded, i => i.JobId == jobId);
        Assert.DoesNotContain(_harness.Published.Select<SignMacroCompleted>(), m => m.Context.Message.JobId == jobId);
    }

    [Fact]
    public async Task SignMacroRequested_ohne_Saga_wird_abgelehnt()
    {
        // Arrange: Keine Saga zum Vorgang
        var jobId = Guid.NewGuid();
        _stateReader.State = null;

        // Act
        await _harness.Bus.Publish(CreateSignMacroRequested(jobId));

        // Assert
        Assert.True(await _harness.Published.Any<JobFailed>(m =>
            m.Context.Message.JobId == jobId && m.Context.Message.Stage == "signing"));
        Assert.Contains(_incidents.Recorded, i => i.JobId == jobId);
    }

    [Fact]
    public async Task SignMacroRequested_mit_SignierungAngefragt_wird_akzeptiert()
    {
        // Arrange: Vorgang korrekt in SignierungAngefragt
        var jobId = Guid.NewGuid();
        _stateReader.State = SagaStateNames.SignierungAngefragt;

        // Act
        await _harness.Bus.Publish(CreateSignMacroRequested(jobId));

        // Assert: keine Ablehnung, kein Vorfall (Übergabe an die Signier-Pipeline, Ticket 08)
        await Task.Delay(TimeSpan.FromMilliseconds(300));
        Assert.False(await _harness.Published.Any<JobFailed>(m => m.Context.Message.JobId == jobId));
        Assert.DoesNotContain(_incidents.Recorded, i => i.JobId == jobId);
        Assert.Equal(SagaStateNames.SignierungAngefragt, await _stateReader.GetSagaStateAsync(jobId, CancellationToken.None));
    }

    private static SignMacroRequested CreateSignMacroRequested(Guid jobId) => new(
        JobId: jobId,
        ArtifactId: Guid.NewGuid(),
        ContentSha256: Convert.ToHexString(System.Security.Cryptography.SHA256.HashData("blob"u8)),
        OriginalFileName: "doku.xlsm",
        ContentType: "xlsm",
        RequestedBy: "system:auto-sign",
        RequestedAt: DateTimeOffset.UtcNow);

    private sealed class FakeSagaStateReader : ISagaStateReader
    {
        public string? State { get; set; }

        public Task<string?> GetSagaStateAsync(Guid jobId, CancellationToken cancellationToken) => Task.FromResult(State);
    }

    private sealed class FakeSigningIncidentWriter : ISigningIncidentWriter
    {
        public List<(Guid JobId, string Reason)> Recorded { get; } = [];

        public Task RecordAsync(Guid jobId, string reason, CancellationToken cancellationToken)
        {
            Recorded.Add((jobId, reason));
            return Task.CompletedTask;
        }
    }
}
