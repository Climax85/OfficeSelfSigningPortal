using MassTransit;
using MassTransit.Testing;
using Microsoft.Extensions.DependencyInjection;
using OfficeSelfSigningPortal.WorkerService.Messaging;
using OfficeSelfSigningPortal.WorkerService.Saga;
using Ossp.Contracts;
using Xunit;

namespace OfficeSelfSigningPortal.Tests.Saga;

/// <summary>
/// Seam S2 (Ticket 10, REQ-08): Die Saga publiziert beim Eintritt in einen
/// Endzustand (Signiert/Abgelehnt/NichtSignierbar/Fehler) oder eine Rückfrage
/// das E-Mail-Auslöseereignis <see cref="BenachrichtigungAusgeloest"/> — mit der
/// Einreicher-Adresse aus ScanRequested und Security-Team-Flag ausschließlich auf
/// dem Malicious-Pfad (REQ-13, TM-02).
/// </summary>
public sealed class AnalysisSagaNotificationTests : IAsyncLifetime
{
    private static readonly OsspRetryOptions TestRetry = new()
    {
        Limit = 2,
        MinDelay = TimeSpan.FromMilliseconds(20),
        MaxDelay = TimeSpan.FromMilliseconds(60),
    };

    private const string SubmitterEmail = "submitter-1@example.org";

    private ServiceProvider _provider = null!;
    private ITestHarness _harness = null!;
    private ISagaStateMachineTestHarness<AnalysisSaga, AnalysisSagaState> _sagaHarness = null!;
    private AnalysisSaga _machine = null!;

    public async Task InitializeAsync()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton<ISagaAuditWriter, NullSagaAuditWriter>();
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

        _provider = services.BuildServiceProvider(true);
        _harness = _provider.GetRequiredService<ITestHarness>();
        _sagaHarness = _provider.GetRequiredService<ISagaStateMachineTestHarness<AnalysisSaga, AnalysisSagaState>>();
        _machine = new AnalysisSaga(new NullSagaAuditWriter());
        await _harness.Start();
    }

    public async Task DisposeAsync()
    {
        await _harness.Stop();
        await _provider.DisposeAsync();
    }

    [Fact]
    public async Task Signiert_erreicht_publiziert_Benachrichtigung_mit_EinreicherEmail()
    {
        // Arrange
        var jobId = Guid.NewGuid();
        await StarteSagaAsync(jobId);
        await _harness.Bus.Publish(CreateScanCompleted(jobId, Verdict.Clean));
        await AssertSagaInStateAsync(jobId, _machine.SignierungAngefragt);

        // Act
        await _harness.Bus.Publish(new SignMacroCompleted(jobId, Guid.NewGuid(), DateTimeOffset.UtcNow));

        // Assert: Endzustand Signiert benachrichtigt den Einreicher, kein Security-Team.
        await AssertSagaInStateAsync(jobId, _machine.Signiert);
        Assert.True(await _harness.Published.Any<BenachrichtigungAusgeloest>(m =>
            m.Context.Message.JobId == jobId
            && m.Context.Message.Zustand == SagaStateNames.Signiert
            && m.Context.Message.SubmitterEmail == SubmitterEmail
            && !m.Context.Message.SecurityTeam));
    }

    [Fact]
    public async Task ScanMalicious_publiziert_Benachrichtigung_mit_SecurityTeamFlag()
    {
        // Arrange (REQ-13: Ablehnung plus Security-Team-Benachrichtigung).
        var jobId = Guid.NewGuid();
        await StarteSagaAsync(jobId);

        // Act
        await _harness.Bus.Publish(CreateScanCompleted(jobId, Verdict.Malicious));

        // Assert: Abgelehnt meldet zusätzlich dem Security-Team (Status + Link, keine Befunde).
        await AssertSagaInStateAsync(jobId, _machine.Abgelehnt);
        Assert.True(await _harness.Published.Any<BenachrichtigungAusgeloest>(m =>
            m.Context.Message.JobId == jobId
            && m.Context.Message.Zustand == SagaStateNames.Abgelehnt
            && m.Context.Message.SecurityTeam));
    }

    [Fact]
    public async Task ReviewAblehnung_publiziert_Benachrichtigung_ohne_SecurityTeamFlag()
    {
        // Arrange: Ablehnung durch den Bearbeiter ist kein Security-Vorfall —
        // nur der Einreicher wird benachrichtigt.
        var jobId = Guid.NewGuid();
        await ReviewAusstehendAsync(jobId);

        // Act
        await _harness.Bus.Publish(new ReviewDecisionRecorded(
            jobId, "reviewer-2", ReviewDecisionValues.Ablehnen, "Verdachtsfall", DateTimeOffset.UtcNow));

        // Assert
        await AssertSagaInStateAsync(jobId, _machine.Abgelehnt);
        Assert.True(await _harness.Published.Any<BenachrichtigungAusgeloest>(m =>
            m.Context.Message.JobId == jobId
            && m.Context.Message.Zustand == SagaStateNames.Abgelehnt
            && !m.Context.Message.SecurityTeam));
    }

    [Fact]
    public async Task ReviewRueckfrage_publiziert_Benachrichtigung()
    {
        // Arrange (REQ-08: Endzustände UND Rückfragen benachrichtigen).
        var jobId = Guid.NewGuid();
        await ReviewAusstehendAsync(jobId);

        // Act
        await _harness.Bus.Publish(new ReviewDecisionRecorded(
            jobId, "reviewer-2", ReviewDecisionValues.Rueckfrage, "Quelle?", DateTimeOffset.UtcNow));

        // Assert
        await AssertSagaInStateAsync(jobId, _machine.RueckfrageAusstehend);
        Assert.True(await _harness.Published.Any<BenachrichtigungAusgeloest>(m =>
            m.Context.Message.JobId == jobId
            && m.Context.Message.Zustand == SagaStateNames.RueckfrageAusstehend
            && m.Context.Message.SubmitterEmail == SubmitterEmail));
    }

    [Fact]
    public async Task SignaturFehlerNichtRetryable_publiziert_FehlerBenachrichtigung()
    {
        // Arrange (Anhang B: SignMacroFailed(Retryable=false) → Fehler + Alarm —
        // der Einreicher wird über den Endzustand informiert).
        var jobId = Guid.NewGuid();
        await StarteSagaAsync(jobId);
        await _harness.Bus.Publish(CreateScanCompleted(jobId, Verdict.Clean));
        await AssertSagaInStateAsync(jobId, _machine.SignierungAngefragt);

        // Act
        await _harness.Bus.Publish(new SignMacroFailed(jobId, "ContentSha256-Mismatch", Retryable: false));

        // Assert
        await AssertSagaInStateAsync(jobId, _machine.Fehler);
        Assert.True(await _harness.Published.Any<BenachrichtigungAusgeloest>(m =>
            m.Context.Message.JobId == jobId
            && m.Context.Message.Zustand == SagaStateNames.Fehler
            && !m.Context.Message.SecurityTeam));
    }

    [Fact]
    public async Task ScanRequested_ohne_EinreicherEmail_publiziert_Benachrichtigung_mitNullAdresse()
    {
        // Arrange: IdP ohne E-Mail-Claim — der Versandpfad entscheidet (Consumer
        // sendet dann nur ans Security-Team bzw. gar nicht), die Saga bleibt fehlerfrei.
        var jobId = Guid.NewGuid();
        await _harness.Bus.Publish(CreateScanRequested(jobId, submitterEmail: null));
        await AssertSagaInStateAsync(jobId, _machine.ScanLaeuft);

        // Act
        await _harness.Bus.Publish(CreateScanCompleted(jobId, Verdict.Malicious));

        // Assert: keine Null-Ref in der Saga, Flag bleibt gesetzt, Adresse null.
        await AssertSagaInStateAsync(jobId, _machine.Abgelehnt);
        Assert.True(await _harness.Published.Any<BenachrichtigungAusgeloest>(m =>
            m.Context.Message.JobId == jobId
            && m.Context.Message.SubmitterEmail is null
            && m.Context.Message.SecurityTeam));
    }

    [Fact]
    public async Task Saga_persistiert_SubmitterEmail_als_Vorgangskontext()
    {
        // Arrange / Act
        var jobId = Guid.NewGuid();
        await _harness.Bus.Publish(CreateScanRequested(jobId));

        // Assert: Die Adresse steht persistiert im Saga-State (Zustellbasis der Mail).
        var matches = await _sagaHarness.Match(s => s.SubmitterEmail == SubmitterEmail);
        Assert.Contains(jobId, matches);
    }

    private async Task AssertSagaInStateAsync(Guid jobId, State state, TimeSpan? timeout = null)
    {
        var gefunden = await _sagaHarness.Exists(jobId, state, timeout ?? TimeSpan.FromSeconds(10));
        Assert.True(gefunden.HasValue, $"Saga {jobId} nicht in Zustand {state.Name}");
    }

    private async Task StarteSagaAsync(Guid jobId)
    {
        await _harness.Bus.Publish(CreateScanRequested(jobId));
        await AssertSagaInStateAsync(jobId, _machine.ScanLaeuft);
    }

    private async Task ReviewAusstehendAsync(Guid jobId)
    {
        await StarteSagaAsync(jobId);
        await _harness.Bus.Publish(CreateScanCompleted(jobId, Verdict.Suspicious));
        await AssertSagaInStateAsync(jobId, _machine.ReviewAusstehend);
    }

    private static ScanRequested CreateScanRequested(Guid jobId, string? submitterEmail = SubmitterEmail) => new(
        JobId: jobId,
        ArtifactId: Guid.NewGuid(),
        ContentSha256: Convert.ToHexString(System.Security.Cryptography.SHA256.HashData("blob"u8)),
        OriginalFileName: "doku.xlsm",
        ContentType: "xlsm",
        FileSizeBytes: 1024,
        SubmittedBy: "submitter-1",
        SubmitterEmail: submitterEmail,
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
}
