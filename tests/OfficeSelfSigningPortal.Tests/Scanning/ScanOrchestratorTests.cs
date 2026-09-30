using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using OfficeSelfSigningPortal.TestSupport;
using OfficeSelfSigningPortal.WorkerService.Scanning;
using OfficeSelfSigningPortal.WorkerService.Scanning.Vba;
using Ossp.Contracts;

namespace OfficeSelfSigningPortal.Tests.Scanning;

/// <summary>
/// Scan-Orchestrator mit injizierbaren Fake-Engines (Seam S3, AK-47): End-to-End-
/// Verdichtung aus Heuristik + Engine-Läufen, Stage-Timeouts mit CancellationToken
/// (TM-15), AMSI-Profile baseline (AK-46) und hardened (TC-19).
/// </summary>
public sealed class ScanOrchestratorTests
{
    private static readonly ScoringOptions ScoringConfig = new();
    private static readonly ScanEnginesOptions EngineConfig = new()
    {
        HeuristicsStageTimeout = TimeSpan.FromSeconds(5),
        YaraStageTimeout = TimeSpan.FromMilliseconds(200),
        ClamAvStageTimeout = TimeSpan.FromMilliseconds(200),
        AmsiStageTimeout = TimeSpan.FromMilliseconds(200),
    };

    private static ScanOrchestrator CreateOrchestrator(IEnumerable<IScanEngine> engines) =>
        new(
            new HeuristicScanEngine(Options.Create(ScoringConfig), new VbaProjectExtractor()),
            engines,
            Options.Create(ScoringConfig),
            Options.Create(EngineConfig),
            NullLogger<ScanOrchestrator>.Instance);

    private static ScanRequested Request() =>
        new(JobId: Guid.NewGuid(), ArtifactId: Guid.NewGuid(), ContentSha256: "x",
            OriginalFileName: "test.xlsm", ContentType: "xlsm", FileSizeBytes: 1,
            SubmittedBy: "user", SubmitterEmail: null, RequestedAt: DateTimeOffset.UtcNow);

    [Fact]
    public async Task Run_CleanesMakro_liefertCleanMitScoreVersionUndAbsentAmsi()
    {
        // Arrange (TC-10): Clean-Makro, keine weiteren Stages deployt (baseline).
        var orchestrator = CreateOrchestrator([]);
        var content = ScanCorpus.CreateXlsm(ScanCorpus.CleanSource);

        // Act
        var completed = await orchestrator.RunAsync(Request(), content, CancellationToken.None);

        // Assert
        Assert.Equal(Verdict.Clean, completed.Verdict);
        Assert.Equal(10, completed.Score);
        Assert.Equal("scoring-v0.1;ruleset-2025-09", completed.ScoreVersion);
        Assert.True(completed.MacroPresent);
        Assert.Single(completed.Findings);
        Assert.Contains(completed.Engines, e => e is { Engine: "amsi", State: EngineState.Absent });
    }

    [Fact]
    public async Task Run_KuratierteFamilienregel_liefertMaliciousUnabhaengigVomPunktstand()
    {
        // Arrange (AK-43/AK-47): YARA-Fake meldet Familientreffer, Heuristik ist clean.
        var options = new ScoringOptions
        {
            YaraRuleScores = { ["Familie_EvilMacro"] = new YaraRuleScore(Points: 40, IsFamily: true) },
        };
        var yaraFake = new FakeEngine("yara", new EngineRun(
            "yara", EngineState.Ok, null,
            [new ScanFinding("yara", "yara-rule", "Familie_EvilMacro", 40, null)]));
        var orchestrator = new ScanOrchestrator(
            new HeuristicScanEngine(Options.Create(options), new VbaProjectExtractor()),
            [yaraFake],
            Options.Create(options),
            Options.Create(EngineConfig),
            NullLogger<ScanOrchestrator>.Instance);
        var content = ScanCorpus.CreateXlsm(ScanCorpus.CleanSource);

        // Act
        var completed = await orchestrator.RunAsync(Request(), content, CancellationToken.None);

        // Assert
        Assert.Equal(Verdict.Malicious, completed.Verdict);
        Assert.Equal(50, completed.Score); // 10 Makro + 40 Familie
    }

    [Fact]
    public async Task Run_AmsiStageAusgefallen_liefertInconclusive()
    {
        // Arrange (TC-19): Profil hardened, AMSI-Bridge antwortet nicht.
        var amsiFake = new FakeEngine("amsi", new EngineRun("amsi", EngineState.Failed, "AMSI-Timeout", []));
        var orchestrator = CreateOrchestrator([amsiFake]);
        var content = ScanCorpus.CreateXlsm(ScanCorpus.CleanSource);

        // Act
        var completed = await orchestrator.RunAsync(Request(), content, CancellationToken.None);

        // Assert
        Assert.Equal(Verdict.Inconclusive, completed.Verdict);
    }

    [Fact]
    public async Task Run_StageTimeout_liefertFailedAberScanLaueftWeiter()
    {
        // Arrange (TM-15): eine Stage hängt endlos, die andere liefert normal.
        var hanging = new FakeEngine("clamav", new EngineRun("clamav", EngineState.Ok, null, []), hangUntilCancelled: true);
        var healthy = new FakeEngine("yara", new EngineRun("yara", EngineState.Ok, null, []));
        var orchestrator = CreateOrchestrator([hanging, healthy]);
        var content = ScanCorpus.CreateXlsm(ScanCorpus.CleanSource);

        // Act
        var completed = await orchestrator.RunAsync(Request(), content, CancellationToken.None);

        // Assert
        Assert.Contains(completed.Engines, e => e is { Engine: "clamav", State: EngineState.Failed });
        Assert.Contains(completed.Engines, e => e is { Engine: "yara", State: EngineState.Ok });
        Assert.Equal(Verdict.Clean, completed.Verdict); // Baseline bildet Verdichte aus dem Verfügbaren.
    }

    [Fact]
    public async Task Run_StageWirftException_liefertFailedAberScanLaueftWeiter()
    {
        // Arrange: Engine-Wurf wird verdichtet, nicht weitergereicht.
        var throwing = new ThrowingEngine("clamav");
        var orchestrator = CreateOrchestrator([throwing]);
        var content = ScanCorpus.CreateXlsm(ScanCorpus.CleanSource);

        // Act
        var completed = await orchestrator.RunAsync(Request(), content, CancellationToken.None);

        // Assert
        Assert.Contains(completed.Engines, e => e is { Engine: "clamav", State: EngineState.Failed });
        Assert.Equal(Verdict.Clean, completed.Verdict);
    }

    [Fact]
    public async Task Run_VerschluesseltesVbaProjekt_liefertError()
    {
        // Arrange (TC-15): verschlüsseltes Projekt → Error/Review-Pflicht, niemals Clean.
        var orchestrator = CreateOrchestrator([]);
        var content = ScanCorpus.CreateEncryptedVbaXlsm();

        // Act
        var completed = await orchestrator.RunAsync(Request(), content, CancellationToken.None);

        // Assert
        Assert.Equal(Verdict.Error, completed.Verdict);
    }

    private sealed class FakeEngine(
        string name, EngineRun result, bool hangUntilCancelled = false) : IScanEngine
    {
        public string EngineName => name;

        public async Task<EngineRun> ScanAsync(ScanTarget target, CancellationToken cancellationToken)
        {
            if (hangUntilCancelled)
            {
                await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
            }

            await Task.Yield();
            return result;
        }
    }

    private sealed class ThrowingEngine(string name) : IScanEngine
    {
        public string EngineName => name;

        public Task<EngineRun> ScanAsync(ScanTarget target, CancellationToken cancellationToken) =>
            throw new IOException("clamd-Verbindung abgebrochen");
    }
}
