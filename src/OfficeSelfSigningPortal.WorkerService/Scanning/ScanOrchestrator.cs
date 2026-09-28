using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using OfficeSelfSigningPortal.WorkerService.Scanning.Vba;
using Ossp.Contracts;

namespace OfficeSelfSigningPortal.WorkerService.Scanning;

/// <summary>
/// Scan-Orchestrator (REQ-12, Seam S3): führt die Heuristik-Stage und alle deployten
/// Engine-Stages (ClamAV, YARA, optional AMSI) mit je eigenem CancellationToken-Timeout
/// aus (TM-15), verdichtet die Funde über <see cref="Scoring"/> und <see cref="VerdictPolicy"/>
/// zu einem <see cref="ScanCompleted"/> (Anhang A) und ergänzt die AMSI-Stage als
/// <see cref="EngineState.Absent"/>, wenn sie nicht deployt ist (AK-46, Profil baseline).
///
/// Engine-Ausfälle führen nicht zum Scan-Abbau: Baseline-Stages melden Failed und der
/// Verdichte bildet sich aus dem, was verfügbar war — nur der AMSI-Ausfall der Stufe
/// hardened eskaliert zwingend zu <see cref="Verdict.Inconclusive"/> (TC-19).
/// </summary>
public sealed class ScanOrchestrator(
    HeuristicScanEngine heuristics,
    IEnumerable<IScanEngine> engines,
    IOptions<ScoringOptions> scoringOptions,
    IOptions<ScanEnginesOptions> engineOptions,
    ILogger<ScanOrchestrator> logger)
{
    public async Task<ScanCompleted> RunAsync(ScanRequested request, byte[] content, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(content);

        var scoring = scoringOptions.Value;
        var engineConfig = engineOptions.Value;
        var target = new ScanTarget(content, request.OriginalFileName, request.ContentType);

        var heuristicResult = await RunHeuristicsStage(target, engineConfig.HeuristicsStageTimeout, cancellationToken);

        var runs = new List<EngineRun>();
        var findings = heuristicResult.Findings.ToList();

        foreach (var engine in engines)
        {
            var run = await RunStage(engine, target, TimeoutFor(engine.EngineName, engineConfig), cancellationToken);
            runs.Add(run);
            findings.AddRange(run.Findings);
        }

        if (runs.All(r => r.Engine != FindingSources.Amsi))
        {
            // Profil baseline: AMSI-Bridge nicht deployt — verbindlich als Absent melden (AK-46, TC-18).
            runs.Add(new EngineRun(
                Engine: FindingSources.Amsi,
                State: EngineState.Absent,
                Detail: "AMSI-Bridge nicht deployt (Profil baseline)",
                Findings: []));
        }

        var score = Scoring.Score(scoring, findings);
        var verdict = VerdictPolicy.Decide(scoring, heuristicResult, runs, score, findings);

        logger.LogInformation(
            "Scan {JobId} abgeschlossen: Verdict {Verdict}, Score {Score} ({ScoreVersion}), {FindingCount} Funde, Engine-States: {EngineStates}",
            request.JobId,
            verdict,
            score,
            scoring.ScoreVersion,
            findings.Count,
            string.Join(", ", runs.Select(r => $"{r.Engine}={r.State}")));

        return new ScanCompleted(
            JobId: request.JobId,
            Verdict: verdict,
            Score: score,
            ScoreVersion: scoring.ScoreVersion,
            Findings: findings,
            Engines: runs.Select(r => new EngineResult(r.Engine, r.State, r.Detail)).ToList(),
            MacroPresent: heuristicResult.MacroPresent,
            ModuleCount: heuristicResult.ModuleCount,
            CompletedAt: DateTimeOffset.UtcNow);
    }

    private async Task<HeuristicScanResult> RunHeuristicsStage(
        ScanTarget target, TimeSpan timeout, CancellationToken cancellationToken)
    {
        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutCts.CancelAfter(timeout);

        try
        {
            return await heuristics.ScanAsync(target, timeoutCts.Token);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            // Heuristik-Timeout: ohne Quelltextanalyse kein belastbarer Verdichte — Error/Review.
            logger.LogWarning("Heuristik-Stage hat das Timeout {Timeout} überschritten", timeout);
            return new HeuristicScanResult([], MacroPresent: false, ModuleCount: 0, EncryptedProject: false, ParserError: true);
        }
    }

    private async Task<EngineRun> RunStage(
        IScanEngine engine, ScanTarget target, TimeSpan timeout, CancellationToken cancellationToken)
    {
        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutCts.CancelAfter(timeout);

        try
        {
            return await engine.ScanAsync(target, timeoutCts.Token);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            logger.LogWarning("Engine-Stage {Engine} hat das Timeout {Timeout} überschritten", engine.EngineName, timeout);
            return new EngineRun(engine.EngineName, EngineState.Failed, $"Stage-Timeout nach {timeout}", []);
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Engine-Stage {Engine} ist fehlgeschlagen", engine.EngineName);
            return new EngineRun(engine.EngineName, EngineState.Failed, ex.GetType().Name, []);
        }
    }

    private static TimeSpan TimeoutFor(string engineName, ScanEnginesOptions options) =>
        engineName switch
        {
            FindingSources.Yara => options.YaraStageTimeout,
            FindingSources.ClamAv => options.ClamAvStageTimeout,
            FindingSources.Amsi => options.AmsiStageTimeout,
            _ => options.HeuristicsStageTimeout,
        };
}
