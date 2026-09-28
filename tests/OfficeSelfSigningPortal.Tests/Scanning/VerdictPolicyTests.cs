using OfficeSelfSigningPortal.WorkerService.Scanning;
using Ossp.Contracts;

namespace OfficeSelfSigningPortal.Tests.Scanning;

/// <summary>
/// Verdict-Policy (Anhang D): Schwellwerte, Eskalationsregeln unabhängig vom
/// Punktstand (AK-42/AK-43/AK-44), Pflicht-Fehlerpfade (AK-45) und das
/// AMSI-Verhalten der Profile baseline/hardened (AK-46, TC-19). Pure Funktion,
/// erwartete Werte aus dem Scoring-Modell, nicht aus der Implementierung.
/// </summary>
public sealed class VerdictPolicyTests
{
    private static readonly ScoringOptions Default = new();

    private static HeuristicScanResult Heuristik(int scoreRelevant = 0) =>
        new(Findings: scoreRelevant > 0
            ? new[] { Neu("structure", "macro-present", scoreRelevant) }
            : Array.Empty<ScanFinding>(),
        MacroPresent: true,
        ModuleCount: 1,
        EncryptedProject: false,
        ParserError: false);

    private static ScanFinding Neu(string category, string ruleId, int points, string source = "heuristic") =>
        new(Source: source, Category: category, RuleId: ruleId, Points: points, Detail: null);

    private static EngineRun Run(string engine, EngineState state, params ScanFinding[] findings) =>
        new(Engine: engine, State: state, Detail: null, Findings: findings);

    [Fact]
    public void Decide_MraptorRegel_ergibtMindestensSuspiciousUnabhaengigVomPunktstand()
    {
        // Arrange: Score 5 — unter jeder Schwelle, aber mraptor-awx gefunden (AK-42, TC-12).
        var findings = new[] { Neu("autoexec", "mraptor-awx", 30) };

        // Act
        var verdict = VerdictPolicy.Decide(Default, Heuristik(), Array.Empty<EngineRun>(), 5, findings);

        // Assert
        Assert.Equal(Verdict.Suspicious, verdict);
    }

    [Fact]
    public void Decide_MraptorRegelMitHohemScore_ergibtMalicious()
    {
        // Arrange: mraptor-Floor hebt nur an, senkt nie.
        var findings = new[] { Neu("autoexec", "mraptor-awx", 30) };

        // Act
        var verdict = VerdictPolicy.Decide(Default, Heuristik(), Array.Empty<EngineRun>(), 70, findings);

        // Assert
        Assert.Equal(Verdict.Malicious, verdict);
    }

    [Fact]
    public void Decide_KuratierteYaraFamilienregel_ergibtMaliciousUnabhaengigVomPunktstand()
    {
        // Arrange: Score 0, nur ein Familien-Finding (AK-43, TC-13).
        var options = new ScoringOptions
        {
            YaraRuleScores = { ["Familie_EvilMacro"] = new YaraRuleScore(Points: 40, IsFamily: true) },
        };
        var findings = new[] { Neu("yara-rule", "Familie_EvilMacro", 40, source: "yara") };

        // Act
        var verdict = VerdictPolicy.Decide(options, Heuristik(), Array.Empty<EngineRun>(), 0, findings);

        // Assert
        Assert.Equal(Verdict.Malicious, verdict);
    }

    [Fact]
    public void Decide_GenerischeYaraRegelOhneFamilie_keinFloor()
    {
        // Arrange: generischer YARA-Treffer (+10) bleibt unter der Clean-Schwelle.
        var options = new ScoringOptions
        {
            YaraRuleScores = { ["Contains_VbaProject"] = new YaraRuleScore(Points: 10, IsFamily: false) },
        };
        var findings = new[] { Neu("yara-rule", "Contains_VbaProject", 10, source: "yara") };

        // Act
        var verdict = VerdictPolicy.Decide(options, Heuristik(), Array.Empty<EngineRun>(), 10, findings);

        // Assert
        Assert.Equal(Verdict.Clean, verdict);
    }

    [Fact]
    public void Decide_ClamAvFund_ergibtMaliciousUnabhaengigVomPunktstand()
    {
        // Arrange: Score 0, ClamAV meldet einen Fund (AK-44, TC-14).
        var runs = new[] { Run("clamav", EngineState.Ok, Neu("av", "clamav-testfund", 0, source: "clamav")) };

        // Act
        var verdict = VerdictPolicy.Decide(Default, Heuristik(), runs, 0, Array.Empty<ScanFinding>());

        // Assert
        Assert.Equal(Verdict.Malicious, verdict);
    }

    [Fact]
    public void Decide_ClamAvNurOkOhneFund_keinMalicious()
    {
        // Arrange
        var runs = new[] { Run("clamav", EngineState.Ok) };

        // Act
        var verdict = VerdictPolicy.Decide(Default, Heuristik(), runs, 5, Array.Empty<ScanFinding>());

        // Assert
        Assert.Equal(Verdict.Clean, verdict);
    }

    [Fact]
    public void Decide_VerschluesseltesVbaProjekt_ergibtErrorUndNiemalsClean()
    {
        // Arrange: sogar Score 0 mit ansonsten sauberem Befund (AK-45, TC-15).
        var heuristik = Heuristik() with { EncryptedProject = true };

        // Act
        var verdict = VerdictPolicy.Decide(Default, heuristik, Array.Empty<EngineRun>(), 0, Array.Empty<ScanFinding>());

        // Assert
        Assert.Equal(Verdict.Error, verdict);
    }

    [Fact]
    public void Decide_ParserFehler_ergibtErrorUndNiemalsClean()
    {
        // Arrange
        var heuristik = Heuristik() with { ParserError = true };

        // Act
        var verdict = VerdictPolicy.Decide(Default, heuristik, Array.Empty<EngineRun>(), 0, Array.Empty<ScanFinding>());

        // Assert
        Assert.Equal(Verdict.Error, verdict);
    }

    [Fact]
    public void Decide_BaselineOhneAmsi_ergibtEngineAbsentUndVerdictNurAusBaseline()
    {
        // Arrange: AMSI-Stage nicht deployt → Absent, kein Inconclusive (AK-46, TC-18).
        var runs = new[] { Run("amsi", EngineState.Absent), Run("clamav", EngineState.Ok) };

        // Act
        var verdict = VerdictPolicy.Decide(Default, Heuristik(), runs, 5, Array.Empty<ScanFinding>());

        // Assert
        Assert.Equal(Verdict.Clean, verdict);
    }

    [Fact]
    public void Decide_HardenedMitAusgefallenerAmsi_ergibtInconclusive()
    {
        // Arrange: AMSI deployt, aber Failed — Review-Pflicht, kein Auto-Signing (TC-19, AK-26).
        var runs = new[] { Run("amsi", EngineState.Failed, Neu("av", "amsi-timeout", 0, source: "amsi")) };

        // Act
        var verdict = VerdictPolicy.Decide(Default, Heuristik(), runs, 5, Array.Empty<ScanFinding>());

        // Assert
        Assert.Equal(Verdict.Inconclusive, verdict);
    }

    [Fact]
    public void Decide_HardenedMitDegradierterAmsi_ergibtInconclusive()
    {
        // Arrange: Teilausfall zählt wie Ausfall — kein Verdict auf unvollständiger Engine-Basis.
        var runs = new[] { Run("amsi", EngineState.Degraded) };

        // Act
        var verdict = VerdictPolicy.Decide(Default, Heuristik(), runs, 0, Array.Empty<ScanFinding>());

        // Assert
        Assert.Equal(Verdict.Inconclusive, verdict);
    }

    [Fact]
    public void Decide_ErrorDurchVerschluesseltesProjekt_hatVorrangVorInconclusive()
    {
        // Arrange: beide Pflicht-Fehlerpfade — Parser/Encryption ist der härtere Pfad.
        var heuristik = Heuristik() with { EncryptedProject = true };
        var runs = new[] { Run("amsi", EngineState.Failed) };

        // Act
        var verdict = VerdictPolicy.Decide(Default, heuristik, runs, 0, Array.Empty<ScanFinding>());

        // Assert
        Assert.Equal(Verdict.Error, verdict);
    }

    [Fact]
    public void Decide_ClamAvFundUndVerschluesseltesProjekt_ErrorHatVorrang()
    {
        // Arrange: Encryption blockiert jede Verdikt-Bildung über dem Quelltext.
        var heuristik = Heuristik() with { EncryptedProject = true };
        var runs = new[] { Run("clamav", EngineState.Ok, Neu("av", "clamav-fund", 0, source: "clamav")) };

        // Act
        var verdict = VerdictPolicy.Decide(Default, heuristik, runs, 0, Array.Empty<ScanFinding>());

        // Assert
        Assert.Equal(Verdict.Error, verdict);
    }
}
