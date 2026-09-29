using OfficeSelfSigningPortal.WorkerService.Scanning;
using Ossp.Contracts;

namespace OfficeSelfSigningPortal.Tests.Scanning;

/// <summary>
/// Scoring-Modell v0.1 (Anhang D) als pure Funktion — additive Punkte mit
/// Kategorie-Caps, deterministisch (AK-41, TC-17). Erwartete Werte stammen aus
/// der Anhang-D-Punktetabelle, nicht aus der Implementierung.
/// </summary>
public sealed class ScoringTests
{
    private static readonly ScoringOptions Default = new();

    private static ScanFinding Finding(string category, string ruleId, int points) =>
        new(Source: "heuristic", Category: category, RuleId: ruleId, Points: points, Detail: null);

    [Theory]
    [InlineData(19, Verdict.Clean)]
    [InlineData(20, Verdict.Suspicious)]
    [InlineData(59, Verdict.Suspicious)]
    [InlineData(60, Verdict.Malicious)]
    public void VerdictFromScore_SchwellwertGrenzfaelle_LiefertExaktErwartetenVerdict(int score, Verdict erwartet)
    {
        // Arrange
        var options = new ScoringOptions();

        // Act
        var verdict = VerdictPolicy.VerdictFromScore(options, score);

        // Assert
        Assert.Equal(erwartet, verdict);
    }

    [Fact]
    public void Score_EinzelneSignale_EntsprichtAnhangD()
    {
        // Arrange
        var findings = new[]
        {
            Finding(FindingCategories.Structure, "macro-present", 10),
            Finding(FindingCategories.AutoExec, "autoexec-AutoOpen", 15),
            Finding(FindingCategories.YaraRule, "yara-generisch", 10),
        };

        // Act
        var score = Scoring.Score(Default, findings);

        // Assert
        Assert.Equal(35, score);
    }

    [Fact]
    public void Score_VerhaltensKeywordsUeberCap_WirdAufCapBegrenzt()
    {
        // Arrange: 4 Verhaltensgruppen à 10 Punkte — Anhang D cappt bei +30.
        var findings = new[]
        {
            Finding(FindingCategories.SuspiciousKeyword, "behavior-shell", 10),
            Finding(FindingCategories.SuspiciousKeyword, "behavior-object-creation", 10),
            Finding(FindingCategories.SuspiciousKeyword, "behavior-filesystem", 10),
            Finding(FindingCategories.SuspiciousKeyword, "behavior-download", 10),
        };

        // Act
        var score = Scoring.Score(Default, findings);

        // Assert
        Assert.Equal(30, score);
    }

    [Fact]
    public void Score_ObfuscationUeberCap_WirdAufCapBegrenzt()
    {
        // Arrange: 4 Obfuscation-Typen à 10 Punkte — Anhang D cappt bei +25.
        var findings = new[]
        {
            Finding(FindingCategories.Obfuscation, "obfuscation-hex", 10),
            Finding(FindingCategories.Obfuscation, "obfuscation-base64", 10),
            Finding(FindingCategories.Obfuscation, "obfuscation-strreverse", 10),
            Finding(FindingCategories.Obfuscation, "obfuscation-chr-density", 10),
        };

        // Act
        var score = Scoring.Score(Default, findings);

        // Assert
        Assert.Equal(25, score);
    }

    [Fact]
    public void Score_CapsWirkenProKategorie_NichtGlobal()
    {
        // Arrange: Cap-Begrenzung darf andere Kategorien nicht mit kürzen
        // (30 Behavior + 25 Obfuscation + 10 Makro + 15 AutoExec + 30 mraptor = 110 → Clamp 100).
        var findings = new[]
        {
            Finding(FindingCategories.Structure, "macro-present", 10),
            Finding(FindingCategories.AutoExec, "autoexec-AutoOpen", 15),
            Finding(FindingCategories.AutoExec, "mraptor-awx", 30),
            Finding(FindingCategories.SuspiciousKeyword, "behavior-shell", 10),
            Finding(FindingCategories.SuspiciousKeyword, "behavior-filesystem", 10),
            Finding(FindingCategories.SuspiciousKeyword, "behavior-download", 10),
            Finding(FindingCategories.SuspiciousKeyword, "behavior-object-creation", 10),
            Finding(FindingCategories.Obfuscation, "obfuscation-hex", 10),
            Finding(FindingCategories.Obfuscation, "obfuscation-base64", 10),
            Finding(FindingCategories.Obfuscation, "obfuscation-strreverse", 10),
        };

        // Act
        var score = Scoring.Score(Default, findings);

        // Assert
        Assert.Equal(100, score);
    }

    [Fact]
    public void Score_IoCsTragenKeinePunkte_LiefernNurFindings()
    {
        // Arrange
        var findings = new[]
        {
            Finding(FindingCategories.Ioc, "ioc-url", 0),
            Finding(FindingCategories.Structure, "macro-present", 10),
        };

        // Act
        var score = Scoring.Score(Default, findings);

        // Assert
        Assert.Equal(10, score);
    }
}
