using Microsoft.Extensions.Options;
using OfficeSelfSigningPortal.TestSupport;
using OfficeSelfSigningPortal.WorkerService.Scanning;
using OfficeSelfSigningPortal.WorkerService.Scanning.Vba;

namespace OfficeSelfSigningPortal.Tests.Scanning;

/// <summary>
/// Heuristik-Scorer (Anhang D): Struktur-Fund, AutoExec-Keywords, Verhaltens-Gruppen
/// mit Cap, Obfuscation-Typen mit Cap, mraptor-Regel A ∧ (W ∨ X) (AK-42), IOC-Anreicherung
/// (0 Punkte). Erwartete Scores sind aus der Anhang-D-Punktetabelle abgeleitet.
/// </summary>
public sealed class HeuristicScanEngineTests
{
    private static readonly ScoringOptions Default = new();
    private readonly HeuristicScanEngine _engine = new(Options.Create(Default), new VbaProjectExtractor());

    private static ScanTarget Target(byte[] content) =>
        new(Content: content, OriginalFileName: "test.xlsm", ContentType: "xlsm");

    [Fact]
    public async Task Scan_CleanesMakro_liefertNurMacroPresentMitZehnPunkten()
    {
        // Arrange
        var target = Target(ScanCorpus.CreateXlsm(ScanCorpus.CleanSource));

        // Act
        var result = await _engine.ScanAsync(target, CancellationToken.None);

        // Assert
        Assert.True(result.MacroPresent);
        Assert.Equal(1, result.ModuleCount);
        Assert.False(result.EncryptedProject);
        Assert.False(result.ParserError);
        var finding = Assert.Single(result.Findings);
        Assert.Equal(FindingCategories.Structure, finding.Category);
        Assert.Equal("macro-present", finding.RuleId);
        Assert.Equal(10, finding.Points);
    }

    [Fact]
    public async Task Scan_VerhaltensKeywords_liefertAutoExecGruppenUndMraptor()
    {
        // Arrange: 10 (Makro) + 15 (AutoOpen) + 30 (Verhaltens-Cap) + 30 (mraptor) = 85.
        var target = Target(ScanCorpus.CreateXlsm(ScanCorpus.VerhaltensSource));

        // Act
        var result = await _engine.ScanAsync(target, CancellationToken.None);

        // Assert
        Assert.Contains(result.Findings, f => f.RuleId == "autoexec-AutoOpen" && f.Points == 15);
        Assert.Contains(result.Findings, f => f.RuleId == "behavior-shell-exec");
        Assert.Contains(result.Findings, f => f.RuleId == "behavior-object-creation");
        Assert.Contains(result.Findings, f => f.RuleId == "behavior-filesystem");
        Assert.Contains(result.Findings, f => f.RuleId == "behavior-download");
        Assert.Contains(result.Findings, f => f.RuleId == VerdictPolicy.MraptorRuleId && f.Points == 30);
        Assert.Equal(85, Scoring.Score(Default, result.Findings));
    }

    [Fact]
    public async Task Scan_Obfuskation_liefertVierTypenMitCap25()
    {
        // Arrange: Verhaltens-Score 85 + Obfuscation-Cap 25 = 110 → Clamp 100.
        var target = Target(ScanCorpus.CreateXlsm(ScanCorpus.ObfuskationsSource));

        // Act
        var result = await _engine.ScanAsync(target, CancellationToken.None);

        // Assert
        Assert.Contains(result.Findings, f => f.RuleId == "obfuscation-hex");
        Assert.Contains(result.Findings, f => f.RuleId == "obfuscation-strreverse");
        Assert.Contains(result.Findings, f => f.RuleId == "obfuscation-base64");
        Assert.Contains(result.Findings, f => f.RuleId == "obfuscation-chr-density");
        Assert.Equal(100, Scoring.Score(Default, result.Findings));
    }

    [Fact]
    public async Task Scan_VerschluesseltesProjekt_liefertEncryptedFlagOhneKeywordFunde()
    {
        // Arrange
        var target = Target(ScanCorpus.CreateEncryptedVbaXlsm());

        // Act
        var result = await _engine.ScanAsync(target, CancellationToken.None);

        // Assert
        Assert.True(result.EncryptedProject);
        Assert.Empty(result.Findings);
    }

    [Fact]
    public async Task Scan_IoCs_liefertAnreicherungMitNullPunkten()
    {
        // Arrange: Verhaltens-Quelltext enthält URL und EXE-Name.
        var target = Target(ScanCorpus.CreateXlsm(ScanCorpus.VerhaltensSource));

        // Act
        var result = await _engine.ScanAsync(target, CancellationToken.None);

        // Assert
        Assert.Contains(result.Findings, f => f.Category == FindingCategories.Ioc && f.RuleId == "ioc-url" && f.Points == 0);
        Assert.Contains(result.Findings, f => f.Category == FindingCategories.Ioc && f.RuleId == "ioc-exe" && f.Points == 0);
    }
}
