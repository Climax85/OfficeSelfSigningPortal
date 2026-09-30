using MassTransit;
using MassTransit.Testing;
using Microsoft.Extensions.DependencyInjection;
using OfficeSelfSigningPortal.WorkerService.Messaging;
using OfficeSelfSigningPortal.WorkerService.Saga;
using Ossp.Contracts;

namespace OfficeSelfSigningPortal.Tests.Saga;

/// <summary>
/// Seam S2 (InMemoryTestHarness): vollständige Zustandslogik der AnalysisSaga —
/// alle Anhang-B-Übergänge und Endzustände, SoD-Ablehnung, Retry→DLQ→Fehler (TC-16),
/// Worker-interne Ereignisse. Persistenz über Neustarts (TC-39) und Transport-
/// Vertrauen (AK-40) prüft der RabbitMQ/PostgreSQL-Slice in den Integrationstests.
/// </summary>
public sealed class AnalysisSagaInMemoryTests : IAsyncLifetime
{
    private static readonly OsspRetryOptions TestRetry = new()
    {
        Limit = 2,
        MinDelay = TimeSpan.FromMilliseconds(20),
        MaxDelay = TimeSpan.FromMilliseconds(60),
    };

    private ServiceProvider _provider = null!;
    private ITestHarness _harness = null!;
    private ISagaStateMachineTestHarness<AnalysisSaga, AnalysisSagaState> _sagaHarness = null!;
    private AnalysisSaga _machine = null!;

    public async Task InitializeAsync()
    {
        (_provider, _harness, _sagaHarness, _machine, _) = await CreateHarnessAsync(new NullSagaAuditWriter());
        await _harness.Start();
    }

    public async Task DisposeAsync()
    {
        await _harness.Stop();
        await _provider.DisposeAsync();
    }

    // --- Aufnahme ---

    [Fact]
    public async Task ScanRequested_InitiiertSaga_und_landet_in_ScanLaeuft()
    {
        // Arrange
        var jobId = Guid.NewGuid();
        var message = CreateScanRequested(jobId);

        // Act
        await _harness.Bus.Publish(message);

        // Assert
        await AssertSagaInStateAsync(jobId, _machine.ScanLaeuft);
    }

    [Fact]
    public async Task UploadRegelVerletzt_aus_InValidierung_fuehrt_nach_Abgelehnt()
    {
        // Arrange: Tor am Audit-Writer — die Saga bleibt deterministisch in InValidierung,
        // bis der Ablehnungs-Fall eingereiht ist (Anhang-B-Zweig "Upload-Regel verletzt → Abgelehnt").
        var gate = new GatingSagaAuditWriter();
        var (provider, harness, sagaHarness, machine, _) = await CreateHarnessAsync(gate);
        await using (provider)
        {
            var jobId = Guid.NewGuid();
            await harness.Bus.Publish(CreateScanRequested(jobId));
            await gate.WaitForGateAsync();

            try
            {
                // Act
                await harness.Bus.Publish(new JobFailed(jobId, "ingestion", "Upload-Regel verletzt", false, DateTimeOffset.UtcNow));
            }
            finally
            {
                gate.Release();
            }

            // Assert
            Assert.NotNull(await sagaHarness.Exists(jobId, machine.Abgelehnt, TimeSpan.FromSeconds(10)));
            await harness.Stop();
        }
    }

    [Fact]
    public async Task MakrofreieDatei_aus_InValidierung_fuehrt_nach_NichtSignierbar()
    {
        // Arrange: Tor am Audit-Writer — Anhang-B-Zweig "Datei makrofrei → NichtSignierbar".
        var gate = new GatingSagaAuditWriter();
        var (provider, harness, sagaHarness, machine, _) = await CreateHarnessAsync(gate);
        await using (provider)
        {
            var jobId = Guid.NewGuid();
            await harness.Bus.Publish(CreateScanRequested(jobId));
            await gate.WaitForGateAsync();

            try
            {
                // Act
                await harness.Bus.Publish(new MakrofreieDateiErkannt(jobId));
            }
            finally
            {
                gate.Release();
            }

            // Assert
            Assert.NotNull(await sagaHarness.Exists(jobId, machine.NichtSignierbar, TimeSpan.FromSeconds(10)));
            await harness.Stop();
        }
    }

    // --- Scan-Verdichte ---

    [Fact]
    public async Task ScanClean_fordert_AutoSignierung_an_und_landet_in_SignierungAngefragt()
    {
        // Arrange
        var jobId = Guid.NewGuid();
        await ScanLaeuftAsync(jobId);

        // Act
        await _harness.Bus.Publish(CreateScanCompleted(jobId, Verdict.Clean));

        // Assert
        await AssertSagaInStateAsync(jobId, _machine.SignierungAngefragt);
        Assert.True(await _harness.Published.Any<SignMacroRequested>(m =>
            m.Context.Message.JobId == jobId && m.Context.Message.RequestedBy == "system:auto-sign"));
    }

    [Theory]
    [InlineData(Verdict.Suspicious)]
    [InlineData(Verdict.Inconclusive)]
    public async Task ScanReviewPflicht_landet_in_ReviewAusstehend(Verdict verdict)
    {
        // Arrange
        var jobId = Guid.NewGuid();
        await ScanLaeuftAsync(jobId);

        // Act
        await _harness.Bus.Publish(CreateScanCompleted(jobId, verdict));

        // Assert
        await AssertSagaInStateAsync(jobId, _machine.ReviewAusstehend);
    }

    [Fact]
    public async Task ScanMalicious_fuehrt_nach_Abgelehnt()
    {
        // Arrange
        var jobId = Guid.NewGuid();
        await ScanLaeuftAsync(jobId);

        // Act
        await _harness.Bus.Publish(CreateScanCompleted(jobId, Verdict.Malicious));

        // Assert
        await AssertSagaInStateAsync(jobId, _machine.Abgelehnt);
    }

    [Fact]
    public async Task ScanError_fuehrt_nach_Fehler()
    {
        // Arrange
        var jobId = Guid.NewGuid();
        await ScanLaeuftAsync(jobId);

        // Act
        await _harness.Bus.Publish(CreateScanCompleted(jobId, Verdict.Error));

        // Assert
        await AssertSagaInStateAsync(jobId, _machine.Fehler);
    }

    // --- Review ---

    [Fact]
    public async Task ReviewFreigabe_fordert_Signierung_mit_Reviewer_an()
    {
        // Arrange
        var jobId = Guid.NewGuid();
        await ReviewAusstehendAsync(jobId);

        // Act
        await _harness.Bus.Publish(new ReviewDecisionRecorded(
            jobId, "reviewer-2", ReviewDecisionValues.Freigeben, null, DateTimeOffset.UtcNow));

        // Assert
        await AssertSagaInStateAsync(jobId, _machine.SignierungAngefragt);
        Assert.True(await _harness.Published.Any<SignMacroRequested>(m =>
            m.Context.Message.JobId == jobId && m.Context.Message.RequestedBy == "reviewer-2"));
    }

    [Fact]
    public async Task ReviewAblehnung_fuehrt_nach_Abgelehnt()
    {
        // Arrange
        var jobId = Guid.NewGuid();
        await ReviewAusstehendAsync(jobId);

        // Act
        await _harness.Bus.Publish(new ReviewDecisionRecorded(
            jobId, "reviewer-2", ReviewDecisionValues.Ablehnen, "Verdachtsfall", DateTimeOffset.UtcNow));

        // Assert
        await AssertSagaInStateAsync(jobId, _machine.Abgelehnt);
    }

    [Fact]
    public async Task ReviewRueckfrage_und_EinreicherAntwort_zurueck_in_ReviewAusstehend()
    {
        // Arrange
        var jobId = Guid.NewGuid();
        await ReviewAusstehendAsync(jobId);

        // Act: Anhang-B-Zyklus "RueckfrageAusstehend | Einreicher-Antwort → ReviewAusstehend"
        await _harness.Bus.Publish(new ReviewDecisionRecorded(
            jobId, "reviewer-2", ReviewDecisionValues.Rueckfrage, "Quelle?", DateTimeOffset.UtcNow));
        await AssertSagaInStateAsync(jobId, _machine.RueckfrageAusstehend);

        await _harness.Bus.Publish(new EinreicherAntwortEingegangen(
            jobId, "Interne Vorlage", "submitter-1", DateTimeOffset.UtcNow));

        // Assert
        await AssertSagaInStateAsync(jobId, _machine.ReviewAusstehend);
    }

    [Fact]
    public async Task SoD_Freigabe_durch_Einreicher_wird_abgelehnt_und_Vorgang_bleibt_offen()
    {
        // Arrange (TC-22, REQ-17, TM-18)
        var jobId = Guid.NewGuid();
        await ReviewAusstehendAsync(jobId);

        // Act: Freigabeversuch durch denselben Account, der eingereicht hat
        await _harness.Bus.Publish(new ReviewDecisionRecorded(
            jobId, "submitter-1", ReviewDecisionValues.Freigeben, null, DateTimeOffset.UtcNow));

        // Assert: SoD-Block als JobFailed(Stage "review"), kein Signaturauftrag, Vorgang bleibt ReviewAusstehend
        Assert.True(await _harness.Published.Any<JobFailed>(m =>
            m.Context.Message.JobId == jobId
            && m.Context.Message.Stage == "review"
            && !m.Context.Message.Retryable));
        Assert.False(await _harness.Published.Any<SignMacroRequested>(m => m.Context.Message.JobId == jobId));
        await AssertSagaInStateAsync(jobId, _machine.ReviewAusstehend);
    }

    [Fact]
    public async Task SoD_Blockade_wird_durch_zweiten_Bearbeiter_aufgehoben()
    {
        // Arrange
        var jobId = Guid.NewGuid();
        await ReviewAusstehendAsync(jobId);
        await _harness.Bus.Publish(new ReviewDecisionRecorded(
            jobId, "submitter-1", ReviewDecisionValues.Freigeben, null, DateTimeOffset.UtcNow));
        Assert.True(await _harness.Published.Any<JobFailed>(m => m.Context.Message.JobId == jobId));

        // Act: Freigabe durch einen zweiten, unabhängigen Bearbeiter
        await _harness.Bus.Publish(new ReviewDecisionRecorded(
            jobId, "reviewer-2", ReviewDecisionValues.Freigeben, null, DateTimeOffset.UtcNow));

        // Assert
        await AssertSagaInStateAsync(jobId, _machine.SignierungAngefragt);
    }

    // --- Signierung ---

    [Fact]
    public async Task SignaturErfolgreich_fuehrt_nach_Signiert()
    {
        // Arrange
        var jobId = Guid.NewGuid();
        await SignierungAngefragtAsync(jobId);
        var signedArtifactId = Guid.NewGuid();

        // Act
        await _harness.Bus.Publish(new SignMacroCompleted(jobId, signedArtifactId, DateTimeOffset.UtcNow));

        // Assert
        await AssertSagaInStateAsync(jobId, _machine.Signiert);

        // Assert: SignedArtifactId persistiert (Download TC-27/AK-04 via T09, Retention T11)
        var matches = await _sagaHarness.Match(s => s.SignedArtifactId == signedArtifactId);
        Assert.Contains(jobId, matches);
    }

    [Fact]
    public async Task SignaturFehler_NichtRetryable_fuehrt_nach_Fehler_mit_Alarm()
    {
        // Arrange (TC-29-Verdrahtung: Anhang B "SignMacroFailed(Retryable=false) → Fehler + Alarm")
        var jobId = Guid.NewGuid();
        await SignierungAngefragtAsync(jobId);

        // Act
        await _harness.Bus.Publish(new SignMacroFailed(jobId, "ContentSha256-Mismatch", Retryable: false));

        // Assert
        await AssertSagaInStateAsync(jobId, _machine.Fehler);
        Assert.True(await _harness.Published.Any<JobFailed>(m =>
            m.Context.Message.JobId == jobId && m.Context.Message.Stage == "signing" && !m.Context.Message.Retryable));
    }

    [Fact]
    public async Task SignaturFehler_Retryable_beißt_Saga_in_SignierungAngefragt()
    {
        // Arrange (Anhang B: Retryable → MassTransit-Retry, Saga bleibt im Zustand)
        var jobId = Guid.NewGuid();
        await SignierungAngefragtAsync(jobId);

        // Act
        await _harness.Bus.Publish(new SignMacroFailed(jobId, "Vault temporär nicht erreichbar", Retryable: true));

        // Assert
        await AssertSagaInStateAsync(jobId, _machine.SignierungAngefragt);
        Assert.False((await _sagaHarness.Exists(jobId, _machine.Fehler, TimeSpan.FromSeconds(2))).HasValue);
    }

    // --- Fehlerpfad / DLQ (TC-16, REQ-22, AK-22) ---

    [Fact]
    public async Task RetryLimit_Scanner_landet_im_DLQ_und_Vorgang_zeigt_Fehler()
    {
        // Arrange: Scanner-Stand-in, der dauerhaft fehlschlägt (Consumer verdrahtet Ticket 05)
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton<ISagaAuditWriter, NullSagaAuditWriter>();
        services.AddMassTransitTestHarness(x =>
        {
            x.AddAnalysisSaga(useEntityFrameworkRepository: false);
            x.AddConsumer<ImmerFehlschlagenderScanConsumer>();
            x.UsingInMemory((context, cfg) =>
            {
                cfg.ReceiveEndpoint(QueueNames.AnalysisSaga, e =>
                    AnalysisSagaBusConfiguration.ConfigureSagaEndpoint(e, context, TestRetry, useEntityFrameworkOutbox: false));
                cfg.ReceiveEndpoint(QueueNames.ScanRequested, e =>
                {
                    e.UseMessageRetry(r => r.Intervals(
                        OsspBusConventions.JitteredExponentialIntervals(TestRetry.Limit, TestRetry.MinDelay, TestRetry.MaxDelay)));
                    e.ConfigureConsumer<ImmerFehlschlagenderScanConsumer>(context);
                });
                cfg.ReceiveEndpoint(QueueNames.ScanRequestedError, e =>
                    AnalysisSagaBusConfiguration.ConfigureScanDeadLetterEndpoint(e, context));
            });
        });

        await using var provider = services.BuildServiceProvider(true);
        var harness = provider.GetRequiredService<ITestHarness>();
        var sagaHarness = provider.GetRequiredService<ISagaStateMachineTestHarness<AnalysisSaga, AnalysisSagaState>>();
        var machine = new AnalysisSaga(new NullSagaAuditWriter());
        await harness.Start();

        // Act
        var jobId = Guid.NewGuid();
        await harness.Bus.Publish(CreateScanRequested(jobId));

        // Assert: Retry-Limit → Error-Queue → Dead-Letter-Consumer → JobFailed(Stage "scan") → Fehler
        Assert.NotNull(await sagaHarness.Exists(jobId, machine.ScanLaeuft, TimeSpan.FromSeconds(10)));
        Assert.NotNull(await sagaHarness.Exists(jobId, machine.Fehler, TimeSpan.FromSeconds(30)));
        Assert.True(await harness.Published.Any<JobFailed>(m =>
            m.Context.Message.JobId == jobId && m.Context.Message.Stage == "scan" && !m.Context.Message.Retryable));

        await harness.Stop();
    }

    private static async Task<(ServiceProvider Provider, ITestHarness Harness, ISagaStateMachineTestHarness<AnalysisSaga, AnalysisSagaState> SagaHarness, AnalysisSaga Machine, ISagaAuditWriter Audit)>
        CreateHarnessAsync(ISagaAuditWriter audit)
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton(audit);
        services.AddMassTransitTestHarness(x =>
        {
            x.AddAnalysisSaga(useEntityFrameworkRepository: false);
            x.UsingInMemory((context, cfg) =>
            {
                cfg.ReceiveEndpoint(QueueNames.AnalysisSaga, e =>
                    AnalysisSagaBusConfiguration.ConfigureSagaEndpoint(e, context, TestRetry, useEntityFrameworkOutbox: false));
                cfg.ReceiveEndpoint(QueueNames.ScanRequestedError, e =>
                    AnalysisSagaBusConfiguration.ConfigureScanDeadLetterEndpoint(e, context));
            });
        });

        var provider = services.BuildServiceProvider(true);
        var harness = provider.GetRequiredService<ITestHarness>();
        var sagaHarness = provider.GetRequiredService<ISagaStateMachineTestHarness<AnalysisSaga, AnalysisSagaState>>();
        await harness.Start();
        return (provider, harness, sagaHarness, new AnalysisSaga(audit), audit);
    }


    private async Task AssertSagaInStateAsync(Guid jobId, State state, TimeSpan? timeout = null)
    {
        var gefunden = await _sagaHarness.Exists(jobId, state, timeout ?? TimeSpan.FromSeconds(10));
        Assert.True(gefunden.HasValue, $"Saga {jobId} nicht in Zustand {state.Name}");
    }

    // --- Hilfsmethoden ---

    private async Task StarteSagaAsync(Guid jobId)
    {
        await _harness.Bus.Publish(CreateScanRequested(jobId));
        await AssertSagaInStateAsync(jobId, _machine.ScanLaeuft);
    }

    private async Task ScanLaeuftAsync(Guid jobId) => await StarteSagaAsync(jobId);

    private async Task ReviewAusstehendAsync(Guid jobId)
    {
        await StarteSagaAsync(jobId);
        await _harness.Bus.Publish(CreateScanCompleted(jobId, Verdict.Suspicious));
        await AssertSagaInStateAsync(jobId, _machine.ReviewAusstehend);
    }

    private async Task SignierungAngefragtAsync(Guid jobId)
    {
        await StarteSagaAsync(jobId);
        await _harness.Bus.Publish(CreateScanCompleted(jobId, Verdict.Clean));
        await AssertSagaInStateAsync(jobId, _machine.SignierungAngefragt);
    }

    private static ScanRequested CreateScanRequested(Guid jobId) => new(
        JobId: jobId,
        ArtifactId: Guid.NewGuid(),
        ContentSha256: Convert.ToHexString(System.Security.Cryptography.SHA256.HashData("blob"u8)),
        OriginalFileName: "doku.xlsm",
        ContentType: "xlsm",
        FileSizeBytes: 1024,
        SubmittedBy: "submitter-1",
        SubmitterEmail: "submitter-1@example.org",
        RequestedAt: DateTimeOffset.UtcNow);

    private static ScanCompleted CreateScanCompleted(Guid jobId, Verdict verdict) => new(
        JobId: jobId,
        Verdict: verdict,
        Score: verdict == Verdict.Clean ? 5 : 45,
        ScoreVersion: "scoring-v0.1;ruleset-2025-09",
        Findings: [],
        Engines: [new EngineResult("heuristics", EngineState.Ok, null)],
        MacroPresent: true,
        ModuleCount: 2,
        CompletedAt: DateTimeOffset.UtcNow);

    /// <summary>Stand-in für den Scanner (Ticket 05): wirft zuverlässig, um Retry→DLQ zu treiben.</summary>
    private sealed class ImmerFehlschlagenderScanConsumer : IConsumer<ScanRequested>
    {
        public Task Consume(ConsumeContext<ScanRequested> context)
            => throw new InvalidOperationException("Scanner-Transientfehler (Test-Stand-in)");
    }

    /// <summary>
    /// Hält die Saga beim ersten Übergang deterministisch in <c>InValidierung</c>:
    /// Die Aufnahme publiziert ihr Fortschrittsereignis erst, nachdem der Test das
    /// Zweig-Ereignis eingereiht hat. Verhindert den sonst unvermeidlichen Rennen-
    /// Schluss (Saga schreitet sofort zu ScanLaeuft fort). Timeout als Hang-Schutz.
    /// </summary>
    private sealed class GatingSagaAuditWriter : ISagaAuditWriter
    {
        private readonly TaskCompletionSource _gateEntered = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly TaskCompletionSource _gateRelease = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private int _gateUsed;

        public async Task WaitForGateAsync()
        {
            await _gateEntered.Task;
        }

        public void Release() => _gateRelease.TrySetResult();

        public async Task WriteAsync(
            Guid jobId, string zustand, string ereignis, string aktor, string? detail, CancellationToken cancellationToken)
        {
            if (Interlocked.Exchange(ref _gateUsed, 1) == 0)
            {
                _gateEntered.TrySetResult();
                var released = await Task.WhenAny(_gateRelease.Task, Task.Delay(TimeSpan.FromSeconds(15), cancellationToken));
                if (released != _gateRelease.Task)
                {
                    throw new InvalidOperationException("Tor des GatingSagaAuditWriter wurde nicht rechtzeitig geöffnet.");
                }
            }
        }
    }
}
