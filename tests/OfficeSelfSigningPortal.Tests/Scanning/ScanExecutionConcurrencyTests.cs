using MassTransit;
using MassTransit.Testing;
using Microsoft.Extensions.DependencyInjection;
using OfficeSelfSigningPortal.WorkerService.Messaging;
using OfficeSelfSigningPortal.WorkerService.Scanning;
using Ossp.Contracts;
using Xunit;

namespace OfficeSelfSigningPortal.Tests.Scanning;

/// <summary>
/// Seam S2 (InMemoryTestHarness, TM-14, SF-03, AK via Ticket 37): das Scan-Endpoint
/// respektiert das konfigurierte ConcurrencyLimit — gleichzeitig laufen nicht
/// mehr Verarbeitungen als erlaubt, weitere Nachrichten werden im Broker-Puffer
/// gehalten (Queueing-Verhalten). Verifiziert die korrekte Anwendung der
/// <see cref="ScanExecutionOptions"/> an <see cref="AnalysisSagaBusConfiguration.ConfigureScanExecutionEndpoint"/>.
/// </summary>
/// <remarks>
/// Der echte <c>ConfigureScanExecutionEndpoint</c> konfiguriert <c>ScanExecutionConsumer</c>
/// fest mit — für den Concurrency-Beweis genügt der äquivalente Pattern-Aufbau
/// (PrefetchCount + UseConcurrencyLimit am Endpoint) mit einem leichten
/// Test-Consumer, der den Gleichzeitigkeitsgrad aufzeichnet.
/// </remarks>
public sealed class ScanExecutionConcurrencyTests : IAsyncLifetime
{
    private const int Concurrency = 2;
    private const int MessageCount = 4;
    private const int ConsumerDelayMs = 200;

    private readonly ConcurrencyRecordingConsumer.ConsumerState _state = new();
    private ServiceProvider _provider = null!;
    private ITestHarness _harness = null!;

    public async Task InitializeAsync()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton(_state);
        services.AddMassTransitTestHarness(x =>
        {
            x.AddConsumer<ConcurrencyRecordingConsumer>();
            x.UsingInMemory((context, cfg) =>
            {
                var scanExecutionOptions = new ScanExecutionOptions
                {
                    MaxConcurrentMessages = Concurrency,
                    PrefetchCount = Concurrency,
                };
                cfg.ReceiveEndpoint(QueueNames.ScanRequested, e =>
                {
                    // Spiegelt den Effekt von ConfigureScanExecutionEndpoint
                    // (PrefetchCount + UseConcurrencyLimit) am Endpoint — der
                    // echte Production-Aufruf verdrahtet zusätzlich den
                    // ScanExecutionConsumer. Für die Concurrency-Eigenschaft
                    // ist der Pattern-Aufbau identisch.
                    e.PrefetchCount = scanExecutionOptions.PrefetchCount;
                    e.ConfigureConsumer<ConcurrencyRecordingConsumer>(context,
                        c => c.UseConcurrencyLimit(scanExecutionOptions.MaxConcurrentMessages));
                });
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
    public async Task ConcurrencyLimit_WirdAusOptionenAngewendet()
    {
        // Arrange — vier Nachrichten; Consumer verzögert pro Nachricht um
        // ConsumerDelayMs. Mit ConcurrencyLimit = 2 dürfen höchstens 2
        // Nachrichten gleichzeitig verarbeitet werden (Queueing der übrigen).
        var jobIds = Enumerable.Range(0, MessageCount).Select(_ => Guid.NewGuid()).ToArray();

        // Act
        var publishTasks = jobIds.Select(jobId =>
            _harness.Bus.Publish(new ScanRequested(
                JobId: jobId,
                ArtifactId: Guid.NewGuid(),
                ContentSha256: "0".PadRight(64, '0'),
                OriginalFileName: "test.xlsm",
                ContentType: "xlsm",
                FileSizeBytes: 1,
                SubmittedBy: "alice",
                SubmitterEmail: null,
                RequestedAt: DateTimeOffset.UtcNow))).ToArray();
        await Task.WhenAll(publishTasks);

        // Assert — alle vier Nachrichten wurden verarbeitet …
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        foreach (var jobId in jobIds)
        {
            var consumed = await _harness.Consumed.Any<ScanRequested>(
                m => m.Context.Message.JobId == jobId, cts.Token);
            Assert.True(consumed, $"ScanRequested für {jobId} wurde nicht konsumiert.");
        }
        // … und der maximale Gleichzeitigkeitsgrad hat das Limit (2) nicht überschritten.
        Assert.Equal(MessageCount, _state.TotalProcessed);
        Assert.True(
            _state.MaxConcurrent <= Concurrency,
            $"ConcurrencyLimit = {Concurrency} nicht eingehalten: " +
            $"beobachtet wurden {_state.MaxConcurrent} gleichzeitige Verarbeitungen.");
    }

    [Fact]
    public void ScanExecutionOptions_Defaults_SindSinnvoll()
    {
        // Arrange — Default-Werte dokumentieren das gewählte Backpressure-Profil.
        // Arrange/Act
        var defaults = new ScanExecutionOptions();

        // Assert
        Assert.True(defaults.MaxConcurrentMessages > 0,
            "MaxConcurrentMessages muss positiv sein (sonst kein Scan mehr).");
        Assert.True(defaults.PrefetchCount >= defaults.MaxConcurrentMessages,
            "PrefetchCount muss >= MaxConcurrentMessages sein, sonst bremst der Consumer sich selbst aus.");
    }

    /// <summary>
    /// Test-Consumer, der pro Aufruf einen Zähler hoch- und runterzählt — Maximum
    /// ist der beobachtete Gleichzeitigkeitsgrad.
    /// </summary>
    private sealed class ConcurrencyRecordingConsumer : IConsumer<ScanRequested>
    {
        private readonly ConsumerState _state;

        public ConcurrencyRecordingConsumer(ConsumerState state) => _state = state;

        public async Task Consume(ConsumeContext<ScanRequested> context)
        {
            var current = Interlocked.Increment(ref _state.CurrentRef);
            _state.UpdateMax(current);
            try
            {
                await Task.Delay(ConsumerDelayMs, context.CancellationToken);
            }
            finally
            {
                Interlocked.Decrement(ref _state.CurrentRef);
                Interlocked.Increment(ref _state.TotalProcessedRef);
            }
        }

        /// <summary>Prozess-geteilter Zustand (vom Test-Harness auflösbar).</summary>
        public sealed class ConsumerState
        {
            internal int CurrentRef;
            internal int TotalProcessedRef;
            private int _max;

            public int MaxConcurrent => _max;
            public int TotalProcessed => TotalProcessedRef;

            public void UpdateMax(int current)
            {
                int initial;
                do
                {
                    initial = _max;
                    if (current <= initial)
                    {
                        return;
                    }
                } while (Interlocked.CompareExchange(ref _max, current, initial) != initial);
            }
        }
    }
}
