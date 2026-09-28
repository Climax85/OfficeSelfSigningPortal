namespace Ossp.Contracts;

/// <param name="Source">"heuristic" | "yara" | "clamav" | "amsi" | "olevba-sidecar".</param>
/// <param name="Category">"structure" | "autoexec" | "suspicious-keyword" | "obfuscation" | "ioc" | "yara-rule" | "av".</param>
/// <param name="RuleId">stabile Regel-/Keyword-ID (Konfigurations-Key des Score-Mappings).</param>
/// <param name="Points">Punkte laut Scoring-Modell (Anhang D).</param>
/// <param name="Detail">z. B. gefundener Stream-Name.</param>
public sealed record ScanFinding(
    string Source,
    string Category,
    string RuleId,
    int Points,
    string? Detail);

/// <param name="Engine">"clamav" | "yara" | "heuristics" | "amsi".</param>
/// <param name="State">Betriebszustand der Stage.</param>
/// <param name="Detail">Fehler-/Degradationsbeschreibung.</param>
public sealed record EngineResult(
    string Engine,
    EngineState State,
    string? Detail);

/// <summary>Scan-Ergebnis WorkerService → Saga (Anhang A, exakter Vertrag).</summary>
/// <param name="JobId">Vorgangs-ID.</param>
/// <param name="Verdict">Verdichte laut Anhang D.</param>
/// <param name="Score">0–100, Grundlage des Schwellwert-Modells (Anhang D).</param>
/// <param name="ScoreVersion">z. B. "scoring-v0.1;ruleset-2025-09" — Pflicht für Audit &amp; Kalibrierung.</param>
/// <param name="Findings">strukturierte Einzelfunde.</param>
/// <param name="Engines">Zustand aller Engine-Stages.</param>
/// <param name="MacroPresent">False ⇒ makrofreie Datei (Saga → <c>NichtSignierbar</c>).</param>
/// <param name="ModuleCount">Anzahl der VBA-Module.</param>
/// <param name="CompletedAt">Zeitstempel (UTC).</param>
public sealed record ScanCompleted(
    Guid JobId,
    Verdict Verdict,
    int Score,
    string ScoreVersion,
    IReadOnlyList<ScanFinding> Findings,
    IReadOnlyList<EngineResult> Engines,
    bool MacroPresent,
    int ModuleCount,
    DateTimeOffset CompletedAt);
