using Ossp.Contracts;

namespace OfficeSelfSigningPortal.WorkerService.Scanning;

/// <summary>
/// Additive Punktvergabe des Scoring-Modells v0.1 (Anhang D) — pure Funktion,
/// deterministisch unit-getestet (AK-41, TC-17). Caps wirken pro Kategorie
/// (Verhaltens-Keywords, Obfuscation), das Gesamtergebnis ist auf 0–100 geclamped.
/// </summary>
public static class Scoring
{
    public static int Score(ScoringOptions options, IReadOnlyList<ScanFinding> findings)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(findings);

        var behaviorPoints = 0;
        var obfuscationPoints = 0;
        var rest = 0;

        foreach (var finding in findings)
        {
            if (finding.Category == FindingCategories.SuspiciousKeyword)
            {
                behaviorPoints += finding.Points;
            }
            else if (finding.Category == FindingCategories.Obfuscation)
            {
                obfuscationPoints += finding.Points;
            }
            else
            {
                rest += finding.Points;
            }
        }

        var score = rest
            + Math.Min(behaviorPoints, options.BehaviorGroupCap)
            + Math.Min(obfuscationPoints, options.ObfuscationCap);

        return Math.Clamp(score, 0, 100);
    }
}
