using DefenceTechSecurity.Yarax;
using Microsoft.Extensions.Options;
using Ossp.Contracts;

namespace OfficeSelfSigningPortal.WorkerService.Scanning;

/// <summary>
/// YARA-Stage (Anhang D, TM-05): scannt den Datei-Byte-Stream mit dem kuratierten
/// Regelwerk und mappt Treffer regelnamenbasiert über <see cref="ScoringOptions.YaraRuleScores"/>
/// (Score-Mapping als Config unter Versionskontrolle). Bekannte Familienregeln erzwingen
/// die Mindeststufe <c>Malicious</c> (AK-43); unbekannte Treffer zählen als generischer
/// Verdacht (+10, FP-behaftet, nur Zusatz).
///
/// Engine: YARA-X via DefenceTechSecurity.Yarax (Native-Binaries für linux-x64/arm64,
/// osx, win-x64) — libyara.NET scheidet aus dem Research-Stand (R4) aus Betriebsgründen
/// aus: C++/CLI-IJW, nur Windows-RIDs, im Linux-Container der Anhang-E-Profile nicht
/// deploybar. Regelsyntax- und Namensvertrag bleiben identisch.
/// </summary>
public sealed class YaraScanEngine : IScanEngine, IDisposable
{
    private readonly ScoringOptions _scoring;
    private readonly Yarax _yarax;
    private readonly string _rulesPath;

    public YaraScanEngine(IOptions<ScoringOptions> scoring, IOptions<ScanEnginesOptions> engines)
    {
        _scoring = scoring.Value;
        _rulesPath = Path.GetFullPath(engines.Value.YaraRulesPath);
        _yarax = CompileRules(_rulesPath);
    }

    public string EngineName => FindingSources.Yara;

    public Task<EngineRun> ScanAsync(ScanTarget target, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(target);
        cancellationToken.ThrowIfCancellationRequested();

        // Scan läuft synchron (native yara-x) — Ablauf-Deadline setzt der Orchestrator
        // per CancellationToken-Timeout (TM-15).
        var findings = new List<ScanFinding>();
        foreach (var hit in _yarax.Scan(target.Content))
        {
            if (_scoring.YaraRuleScores.TryGetValue(hit.RuleName, out var configured))
            {
                findings.Add(new ScanFinding(
                    Source: FindingSources.Yara,
                    Category: FindingCategories.YaraRule,
                    RuleId: hit.RuleName,
                    Points: configured.Points,
                    Detail: configured.IsFamily ? "kuratierte Familienregel" : null));
            }
            else
            {
                findings.Add(new ScanFinding(
                    Source: FindingSources.Yara,
                    Category: FindingCategories.YaraRule,
                    RuleId: hit.RuleName,
                    Points: _scoring.YaraGenericPoints,
                    Detail: "nicht im Score-Mapping — generischer Verdacht"));
            }
        }

        return Task.FromResult(new EngineRun(EngineName, EngineState.Ok, null, findings));
    }

    private static Yarax CompileRules(string rulesPath)
    {
        if (!File.Exists(rulesPath))
        {
            throw new InvalidOperationException(
                $"YARA-Regelwerk nicht gefunden: {rulesPath} — Pfad via {ScanEnginesOptions.SectionName}:{nameof(ScanEnginesOptions.YaraRulesPath)} konfigurieren.");
        }

        return Yarax.Compile(File.ReadAllText(rulesPath));
    }

    public void Dispose() => _yarax.Dispose();
}
