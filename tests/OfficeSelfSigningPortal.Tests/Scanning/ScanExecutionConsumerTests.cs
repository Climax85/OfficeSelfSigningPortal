using MassTransit;
using MassTransit.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using OfficeSelfSigningPortal.TestSupport;
using OfficeSelfSigningPortal.WorkerService.Messaging;
using OfficeSelfSigningPortal.WorkerService.Scanning;
using OfficeSelfSigningPortal.WorkerService.Scanning.Vba;
using Ossp.Contracts;

namespace OfficeSelfSigningPortal.Tests.Scanning;

/// <summary>
/// ScanExecutionConsumer (Endpoint ossp.scan-requested, Seam S3): liest den Blob,
/// verifiziert den TOCTOU-Hash (TM-03) und publiziert ScanCompleted (Anhang A).
/// Fehlender Blob → Fault/Retry-Pfad (TC-16); Hash-Mismatch → JobFailed, kein Scan.
/// </summary>
public sealed class ScanExecutionConsumerTests : IAsyncLifetime
{
    private readonly byte[] _blob = ScanCorpus.CreateXlsm(ScanCorpus.CleanSource);
    private ServiceProvider _provider = null!;
    private ITestHarness _harness = null!;

    public async Task InitializeAsync()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton<IOptions<ScoringOptions>>(Options.Create(new ScoringOptions()));
        services.AddSingleton<IOptions<ScanEnginesOptions>>(Options.Create(new ScanEnginesOptions()));
        services.AddSingleton<VbaProjectExtractor>();
        services.AddSingleton<HeuristicScanEngine>();
        services.AddSingleton<ScanOrchestrator>();
        services.AddSingleton<IArtifactBlobStore>(new StubBlobStore(_blob, Sha256(_blob)));
        services.AddMassTransitTestHarness(x =>
        {
            x.AddConsumer<ScanExecutionConsumer>();
            x.UsingInMemory((context, cfg) =>
            {
                cfg.ReceiveEndpoint(QueueNames.ScanRequested, e =>
                    e.ConfigureConsumer<ScanExecutionConsumer>(context));
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
    public async Task Consume_ValiderAuftrag_publiziertScanCompleted()
    {
        // Arrange
        var jobId = Guid.NewGuid();

        // Act
        await _harness.Bus.Publish(CreateRequest(jobId, Sha256(_blob)));

        // Assert
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var published = await _harness.Published.Any<ScanCompleted>(
            m => m.Context.Message.JobId == jobId, cts.Token);
        Assert.True(published);
        var completed = _harness.Published.Select<ScanCompleted>(m => m.Context.Message.JobId == jobId)
            .Select(m => m.Context.Message)
            .First();
        Assert.Equal(Verdict.Clean, completed.Verdict);
        Assert.Equal("scoring-v0.1;ruleset-2025-09", completed.ScoreVersion);
        Assert.True(completed.MacroPresent);
    }

    [Fact]
    public async Task Consume_HashMismatch_publiziertJobFailedOhneScanCompleted()
    {
        // Arrange: Blob existiert, weicht aber vom Auftrags-Hash ab (TM-03).
        var jobId = Guid.NewGuid();

        // Act
        await _harness.Bus.Publish(CreateRequest(jobId, contentSha256: "0".PadRight(64, '0')));

        // Assert
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var failed = await _harness.Published.Any<JobFailed>(
            m => m.Context.Message.JobId == jobId && m.Context.Message.Stage == "scan" && !m.Context.Message.Retryable,
            cts.Token);
        Assert.True(failed);
        using var cts2 = new CancellationTokenSource(TimeSpan.FromSeconds(2));
        var scanCompleted = await _harness.Published.Any<ScanCompleted>(
            m => m.Context.Message.JobId == jobId, cts2.Token);
        Assert.False(scanCompleted);
    }

    private static string Sha256(byte[] content) =>
        Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(content));

    private ScanRequested CreateRequest(Guid jobId, string contentSha256) =>
        new(JobId: jobId, ArtifactId: StubBlobStore.ArtifactId, ContentSha256: contentSha256,
            OriginalFileName: "test.xlsm", ContentType: "xlsm", FileSizeBytes: _blob.LongLength,
            SubmittedBy: "user", SubmitterEmail: null, RequestedAt: DateTimeOffset.UtcNow);

    private sealed class StubBlobStore(byte[] content, string contentSha256) : IArtifactBlobStore
    {
        public static readonly Guid ArtifactId = Guid.NewGuid();

        public Task<ArtifactBlob?> ReadAsync(Guid artifactId, CancellationToken cancellationToken) =>
            Task.FromResult<ArtifactBlob?>(
                artifactId == ArtifactId
                    ? new ArtifactBlob(content, contentSha256)
                    : null);
    }
}
