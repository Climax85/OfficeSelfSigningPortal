using Ossp.Contracts;

namespace OfficeSelfSigningPortal.WorkerService.Scanning;

/// <summary>
/// Ergebnislauf einer Engine-Stage. Eine Stage liefert entweder Funde mit
/// <see cref="EngineState.Ok"/> oder einen Betriebszustand (Degraded/Failed/Absent)
/// mit Beschreibung — ein Engine-Ausfall erzeugt kein Score-Signal, sondern
/// treibt höchstens den Pflicht-Fehlerpfad (AMSI → Inconclusive, TC-19).
/// </summary>
/// <param name="Engine">"clamav" | "yara" | "heuristics" | "amsi" (Anhang A).</param>
/// <param name="State">Betriebszustand der Stage.</param>
/// <param name="Detail">Fehler-/Degradationsbeschreibung.</param>
/// <param name="Findings">Funde der Stage (leer bei Ausfall/Absent).</param>
public sealed record EngineRun(
    string Engine,
    EngineState State,
    string? Detail,
    IReadOnlyList<ScanFinding> Findings);

/// <summary>
/// Ergebnis der Heuristik-Stage inkl. der Strukturinformationen, die nur diese
/// Stage liefern kann (Makro-Präsenz, Modulanzahl, Parser-/Encryption-Zustand).
/// </summary>
/// <param name="Findings">Heuristische Funde (Struktur, Keywords, Obfuscation, IOCs, mraptor).</param>
/// <param name="MacroPresent">True ⇒ VBA-Projekt mit mindestens einem Modul gefunden.</param>
/// <param name="ModuleCount">Anzahl der VBA-Module (ScanCompleted-Vertrag).</param>
/// <param name="EncryptedProject">Verschlüsseltes VBA-Projekt → Verdict <c>Error</c>/Review-Pflicht, nie <c>Clean</c> (AK-45).</param>
/// <param name="ParserError">Nicht entzifferbare Container-Struktur → Verdict <c>Error</c>/Review-Pflicht.</param>
public sealed record HeuristicScanResult(
    IReadOnlyList<ScanFinding> Findings,
    bool MacroPresent,
    int ModuleCount,
    bool EncryptedProject,
    bool ParserError);
