namespace OfficeSelfSigningPortal.WorkerService.Scanning;

/// <summary>
/// Konfiguration des Scoring-Modells v0.1 (Anhang D) — Schwellwerte, Punktwerte und Caps.
/// Jede Änderung an den Werten erfordert einen neuen <see cref="ScoreVersion"/>
/// (REQ-13, TM-05), damit Scans über Änderungen hinweg vergleichbar bleiben.
/// </summary>
public sealed class ScoringOptions
{
    public const string SectionName = "Scanning:Scoring";

    /// <summary>Score streng unter diesem Wert → <c>Clean</c> (Anhang D, Default 20).</summary>
    public int CleanBelowThreshold { get; set; } = 20;

    /// <summary>Score ab diesem Wert → <c>Malicious</c> (Anhang D, Default 60).</summary>
    public int MaliciousAtThreshold { get; set; } = 60;

    public int MacroPresentPoints { get; set; } = 10;

    public int AutoExecKeywordPoints { get; set; } = 15;

    public int BehaviorGroupPoints { get; set; } = 10;

    /// <summary>Cap der Verhaltens-Keyword-Gruppen (Anhang D: je Gruppe +10, Cap +30).</summary>
    public int BehaviorGroupCap { get; set; } = 30;

    public int ObfuscationTypePoints { get; set; } = 10;

    /// <summary>Cap der Obfuscation-Indikatoren (Anhang D: je Typ +10, Cap +25).</summary>
    public int ObfuscationCap { get; set; } = 25;

    public int MraptorPoints { get; set; } = 30;

    public int YaraGenericPoints { get; set; } = 10;

    public int YaraFamilyPoints { get; set; } = 40;

    /// <summary>
    /// Regelname → Score/Punkte und Familien-Status (Anhang D, TM-05: Mapping als Config
    /// unter Versionskontrolle — libyara.NET liefert kein Rule-Meta). Bekannte Familienregeln
    /// erzwingen die Verdict-Mindeststufe <c>Malicious</c> (AK-43); unbekannte Treffer
    /// zählen als generischer Verdacht (+10, FP-behaftet, nur Zusatz).
    /// </summary>
    public Dictionary<string, YaraRuleScore> YaraRuleScores { get; } = new(StringComparer.Ordinal);

    /// <summary>
    /// Version des Scoring-Modells samt Regelwerk-Stand, z. B. <c>scoring-v0.1;ruleset-2025-09</c>.
    /// Pflichtfeld im ScanCompleted (REQ-13, Audit &amp; Kalibrierung).
    /// </summary>
    public string ScoreVersion { get; set; } = "scoring-v0.1;ruleset-2025-09";
}

/// <param name="Points">Punkte des Regel-Treffers laut Anhang D (+40 kuratierte Familienregel, +10 generisch).</param>
/// <param name="IsFamily">Kuratierte Familien-/Campaign-Regel → Verdict-Mindeststufe <c>Malicious</c> (AK-43).</param>
public sealed record YaraRuleScore(int Points, bool IsFamily);
