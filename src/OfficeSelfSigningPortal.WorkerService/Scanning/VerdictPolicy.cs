using Ossp.Contracts;

namespace OfficeSelfSigningPortal.WorkerService.Scanning;

/// <summary>
/// Verdict-Policy des Scoring-Modells v0.1 (Anhang D) — verdichtet Score und
/// Engine-Läufe zu <c>Clean</c>/<c>Suspicious</c>/<c>Malicious</c> plus den
/// Pflicht-Fällen <c>Inconclusive</c>/<c>Error</c>. Pure Funktion, deterministisch.
///
/// Verbindliche Präzedenz (TC-12–TC-19, AK-41–AK-46):
/// 1. Verschlüsseltes VBA-Projekt oder Parser-Fehler → <c>Error</c> (Review-Pflicht, nie Clean; AK-45).
/// 2. ClamAV-Fund → <c>Malicious</c> (AK-44) — unabhängig vom Punktstand und vom AMSI-Zustand;
///    ein eindeutiger Fund aus einer anderen Engine verwandelt einen AMSI-Ausfall nicht in <c>Inconclusive</c> (F1).
/// 3. Ausgefallene/degradierte AMSI-Stage (nur wenn deployt, nie bei Absent) → <c>Inconclusive</c> (TC-19, AK-46).
/// 4. Score-Schwellwerte: &lt; CleanBelow → Clean, &lt; MaliciousAt → Suspicious, sonst Malicious (AK-41).
/// 5. Eskalationsregeln unabhängig vom Punktstand: mraptor-Regel → mindestens Suspicious (AK-42),
///    kuratierte YARA-Familienregel → mindestens Malicious (AK-43).
/// </summary>
public static class VerdictPolicy
{
    public const string MraptorRuleId = "mraptor-awx";

    public static Verdict VerdictFromScore(ScoringOptions options, int score)
    {
        ArgumentNullException.ThrowIfNull(options);
        return score < options.CleanBelowThreshold
            ? Verdict.Clean
            : score < options.MaliciousAtThreshold
                ? Verdict.Suspicious
                : Verdict.Malicious;
    }

    public static Verdict Decide(
        ScoringOptions options,
        HeuristicScanResult heuristics,
        IReadOnlyList<EngineRun> engineRuns,
        int score,
        IReadOnlyList<ScanFinding> findings)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(heuristics);
        ArgumentNullException.ThrowIfNull(engineRuns);
        ArgumentNullException.ThrowIfNull(findings);

        // 1. Pflicht-Fehlerpfade der Heuristik haben Vorrang vor allem anderen.
        if (heuristics.ParserError || heuristics.EncryptedProject)
        {
            return Verdict.Error;
        }

        // 2. ClamAV-Fund → Malicious unabhängig vom Punktstand und vom AMSI-Zustand (AK-44, F1).
        var clamAvDetection = engineRuns.Any(r =>
            r.Engine == FindingSources.ClamAv
            && r.State == EngineState.Ok
            && r.Findings.Any(f => f.Category == FindingCategories.Av));
        if (clamAvDetection)
        {
            return Verdict.Malicious;
        }

        // 3. AMSI nur werten, wenn die Stage deployt ist (Absent = Profil baseline → ignorieren, AK-46);
        //    ohne eindeutigen Fund aus einer anderen Engine bleibt ein Ausfall Inconclusive (AK-26, TM-15).
        var amsi = engineRuns.FirstOrDefault(r => r.Engine == FindingSources.Amsi);
        if (amsi is { State: EngineState.Failed or EngineState.Degraded })
        {
            return Verdict.Inconclusive;
        }

        // 4. Score-basierte Verdichte.
        var verdict = VerdictFromScore(options, score);

        // 5. Eskalationsregeln (heben an, senken nie).
        if (findings.Any(f => f.RuleId == MraptorRuleId))
        {
            verdict = Max(verdict, Verdict.Suspicious);
        }

        if (findings.Any(f =>
                f.Category == FindingCategories.YaraRule
                && options.YaraRuleScores.TryGetValue(f.RuleId, out var ruleScore)
                && ruleScore.IsFamily))
        {
            verdict = Max(verdict, Verdict.Malicious);
        }

        return verdict;
    }

    private static Verdict Max(Verdict a, Verdict b) =>
        (Verdict)Math.Max((int)a, (int)b);
}
