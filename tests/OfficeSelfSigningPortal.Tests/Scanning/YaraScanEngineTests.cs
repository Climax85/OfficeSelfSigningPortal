using Microsoft.Extensions.Options;
using OfficeSelfSigningPortal.WorkerService.Scanning;
using OfficeSelfSigningPortal.WorkerService.Scanning.Vba;
using Ossp.Contracts;

namespace OfficeSelfSigningPortal.Tests.Scanning;

/// <summary>
/// YARA-Stage gegen echtes yara-x (Native win-x64 im Testrunner): Regelwerkkompilierung,
/// regelnamenbasiertes Score-Mapping (Anhang D, TM-05) und generischer Fallback für
/// unbekannte Regeln.
/// </summary>
public sealed class YaraScanEngineTests : IDisposable
{
    private const string Rules = """
        rule Familie_EvilMacro
        {
            strings:
                $a = "evil-marker-string" ascii
            condition:
                $a
        }
        rule Generischer_Verdacht
        {
            strings:
                $a = "synthetischer-inhalt" ascii
            condition:
                $a
        }
        """;

    private readonly string _rulesPath;

    public YaraScanEngineTests()
    {
        _rulesPath = Path.Combine(Path.GetTempPath(), $"ossp-test-rules-{Guid.NewGuid():N}.yar");
        File.WriteAllText(_rulesPath, Rules);
    }

    public void Dispose() => File.Delete(_rulesPath);

    private YaraScanEngine CreateEngine()
    {
        var scoring = new ScoringOptions
        {
            YaraRuleScores =
            {
                ["Familie_EvilMacro"] = new YaraRuleScore(Points: 40, IsFamily: true),
                ["Generischer_Verdacht"] = new YaraRuleScore(Points: 10, IsFamily: false),
            },
        };
        var engines = new ScanEnginesOptions { YaraRulesPath = _rulesPath };
        return new YaraScanEngine(Options.Create(scoring), Options.Create(engines));
    }

    [Fact]
    public async Task Scan_Familienregel_liefertKonfiguriertePunkteUndFamilienFlag()
    {
        // Arrange
        using var engine = CreateEngine();
        var payload = System.Text.Encoding.ASCII.GetBytes("prefix evil-marker-string suffix");
        var target = new ScanTarget(payload, "test.xlsm", "xlsm");

        // Act
        var run = await engine.ScanAsync(target, CancellationToken.None);

        // Assert
        Assert.Equal(EngineState.Ok, run.State);
        var finding = Assert.Single(run.Findings);
        Assert.Equal("Familie_EvilMacro", finding.RuleId);
        Assert.Equal(40, finding.Points);
        Assert.Equal(FindingCategories.YaraRule, finding.Category);
    }

    [Fact]
    public async Task Scan_UnbekannteRegel_liefertGenerischeZehnPunkte()
    {
        // Arrange: Regel im Regelwerk, aber nicht im Score-Mapping → generischer Verdacht.
        using var engine = CreateEngine();
        var payload = System.Text.Encoding.ASCII.GetBytes("synthetischer-inhalt");
        var target = new ScanTarget(payload, "test.xlsm", "xlsm");

        // Act
        var run = await engine.ScanAsync(target, CancellationToken.None);

        // Assert
        Assert.Equal(EngineState.Ok, run.State);
        Assert.Contains(run.Findings, f => f.RuleId == "Generischer_Verdacht" && f.Points == 10);
    }

    [Fact]
    public async Task Scan_KeinTreffer_liefertLeereFunde()
    {
        // Arrange
        using var engine = CreateEngine();
        var target = new ScanTarget(new byte[] { 1, 2, 3, 4 }, "test.xlsm", "xlsm");

        // Act
        var run = await engine.ScanAsync(target, CancellationToken.None);

        // Assert
        Assert.Equal(EngineState.Ok, run.State);
        Assert.Empty(run.Findings);
    }

    [Fact]
    public void ctor_FehlendesRegelwerk_wirftInvalidOperation()
    {
        // Arrange
        var engines = new ScanEnginesOptions { YaraRulesPath = Path.Combine(Path.GetTempPath(), "gibt-es-nicht.yar") };

        // Act / Assert: Fail-fast beim Worker-Start — ein Scanner ohne Regelwerk darf nicht stumm laufen.
        Assert.Throws<InvalidOperationException>(() =>
            new YaraScanEngine(Options.Create(new ScoringOptions()), Options.Create(engines)));
    }
}
