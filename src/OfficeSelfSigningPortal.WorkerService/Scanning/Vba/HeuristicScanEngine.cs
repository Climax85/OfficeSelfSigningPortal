using System.Text.RegularExpressions;
using Microsoft.Extensions.Options;
using Ossp.Contracts;

namespace OfficeSelfSigningPortal.WorkerService.Scanning.Vba;

/// <summary>
/// Eigener Heuristik-Scorer (Anhang D, REQ-12): OpenMcdf-Extraktion, dann
/// mraptor-Logik (A ∧ (W ∨ X)), Keyword-Gruppen, Obfuscation-Indikatoren und
/// IOC-Anreicherung (0 Punkte). Punkte kommen aus <see cref="ScoringOptions"/>
/// (konfigurierbar, jede Änderung → neue ScoreVersion). Verschlüsselte Projekte
/// erzeugen keine Keyword-Funde — die Policy führt auf <c>Error</c> (AK-45).
/// </summary>
public sealed class HeuristicScanEngine(IOptions<ScoringOptions> options, VbaProjectExtractor extractor)
{
    /// <summary>Maximale IOC-Fund-Einträge pro Scan (Anreicherung, kein Score-Signal).</summary>
    private const int MaxIocFindings = 10;

    public async Task<HeuristicScanResult> ScanAsync(ScanTarget target, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(target);
        cancellationToken.ThrowIfCancellationRequested();

        var scoring = options.Value;
        var extraction = await Task.Run(() => extractor.Extract(target.Content), cancellationToken);

        if (extraction.EncryptedProject || extraction.ParserError || !extraction.MacroPresent)
        {
            return new HeuristicScanResult(
                Findings: [],
                MacroPresent: extraction.MacroPresent,
                ModuleCount: extraction.ModuleCount,
                EncryptedProject: extraction.EncryptedProject,
                ParserError: extraction.ParserError);
        }

        var findings = new List<ScanFinding>
        {
            new(
                Source: FindingSources.Heuristic,
                Category: FindingCategories.Structure,
                RuleId: "macro-present",
                Points: scoring.MacroPresentPoints,
                Detail: $"{extraction.ModuleCount} Modul(e)"),
        };

        var sourceText = string.Join('\n', extraction.Modules.Select(m => m.SourceText));

        findings.AddRange(DetectAutoExecKeywords(sourceText, scoring));
        var behaviorFindings = DetectBehaviorGroups(sourceText, scoring);
        findings.AddRange(behaviorFindings);
        findings.AddRange(DetectObfuscation(sourceText, scoring));
        findings.AddRange(DetectIocs(sourceText));

        if (MeetsMraptor(findings))
        {
            findings.Add(new ScanFinding(
                Source: FindingSources.Heuristic,
                Category: FindingCategories.AutoExec,
                RuleId: VerdictPolicy.MraptorRuleId,
                Points: scoring.MraptorPoints,
                Detail: "mraptor: AutoExec ∧ (Write ∨ Execute)"));
        }

        return new HeuristicScanResult(
            Findings: findings,
            MacroPresent: extraction.MacroPresent,
            ModuleCount: extraction.ModuleCount,
            EncryptedProject: false,
            ParserError: false);
    }

    private static IEnumerable<ScanFinding> DetectAutoExecKeywords(string sourceText, ScoringOptions scoring)
    {
        foreach (var (keyword, pattern) in VbaKeywords.AutoExec)
        {
            if (pattern.IsMatch(sourceText))
            {
                yield return new ScanFinding(
                    Source: FindingSources.Heuristic,
                    Category: FindingCategories.AutoExec,
                    RuleId: $"autoexec-{keyword}",
                    Points: scoring.AutoExecKeywordPoints,
                    Detail: keyword);
            }
        }
    }

    private static IReadOnlyList<ScanFinding> DetectBehaviorGroups(string sourceText, ScoringOptions scoring)
    {
        var findings = new List<ScanFinding>();
        foreach (var (group, _, _, patterns) in VbaKeywords.BehaviorGroups)
        {
            if (patterns.Any(p => p.IsMatch(sourceText)))
            {
                findings.Add(new ScanFinding(
                    Source: FindingSources.Heuristic,
                    Category: FindingCategories.SuspiciousKeyword,
                    RuleId: $"behavior-{group}",
                    Points: scoring.BehaviorGroupPoints,
                    Detail: group));
            }
        }

        return findings;
    }

    private static IEnumerable<ScanFinding> DetectObfuscation(string sourceText, ScoringOptions scoring)
    {
        (string RuleId, bool Hit)[] indicators =
        [
            ("obfuscation-hex", VbaKeywords.HexString().IsMatch(sourceText)),
            ("obfuscation-base64", VbaKeywords.Base64Literal().IsMatch(sourceText)),
            ("obfuscation-strreverse", VbaKeywords.StrReverseCall().IsMatch(sourceText)),
            ("obfuscation-chr-density", VbaKeywords.ChrCall().Matches(sourceText).Count >= VbaKeywords.ChrDensityThreshold),
        ];

        foreach (var (ruleId, hit) in indicators)
        {
            if (hit)
            {
                yield return new ScanFinding(
                    Source: FindingSources.Heuristic,
                    Category: FindingCategories.Obfuscation,
                    RuleId: ruleId,
                    Points: scoring.ObfuscationTypePoints,
                    Detail: ruleId);
            }
        }
    }

    private static IEnumerable<ScanFinding> DetectIocs(string sourceText)
    {
        var count = 0;
        foreach (Match match in VbaKeywords.Ioc.Url.Matches(sourceText))
        {
            if (count++ >= MaxIocFindings)
            {
                yield break;
            }

            yield return IocFinding("ioc-url", match.Value);
        }

        foreach (Match match in VbaKeywords.Ioc.IPv4.Matches(sourceText))
        {
            if (count++ >= MaxIocFindings)
            {
                yield break;
            }

            yield return IocFinding("ioc-ipv4", match.Value);
        }

        foreach (Match match in VbaKeywords.Ioc.ExeName.Matches(sourceText))
        {
            if (count++ >= MaxIocFindings)
            {
                yield break;
            }

            yield return IocFinding("ioc-exe", match.Value);
        }
    }

    private static ScanFinding IocFinding(string ruleId, string value) =>
        new(Source: FindingSources.Heuristic, Category: FindingCategories.Ioc, RuleId: ruleId, Points: 0, Detail: value);

    /// <summary>mraptor-Regel (AK-42): Klasse A getroffen und (W oder X) getroffen.</summary>
    private static bool MeetsMraptor(IReadOnlyList<ScanFinding> findings)
    {
        var hasAutoExec = findings.Any(f => f.Category == FindingCategories.AutoExec);
        if (!hasAutoExec)
        {
            return false;
        }

        var hitGroups = findings
            .Where(f => f.Category == FindingCategories.SuspiciousKeyword)
            .Select(f => f.RuleId)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        var hasWrite = VbaKeywords.BehaviorGroups.Any(g => g.IsWriteClass && hitGroups.Contains($"behavior-{g.Group}"));
        var hasExecute = VbaKeywords.BehaviorGroups.Any(g => g.IsExecuteClass && hitGroups.Contains($"behavior-{g.Group}"));
        return hasWrite || hasExecute;
    }
}
