using OfficeSelfSigningPortal.TestSupport;
using OfficeSelfSigningPortal.WorkerService.Scanning;
using OfficeSelfSigningPortal.WorkerService.Scanning.Vba;

namespace OfficeSelfSigningPortal.Tests.Scanning;

/// <summary>
/// VBA-Projekt-Extraktion (OpenMcdf + MS-OVBA-RLE): OOXML-vbaProject.bin, Struktur-
/// Erkennung, Modul-Quelltexte und die Pflicht-Fehlerpfade verschlüsseltes Projekt
/// (AK-45) sowie Parser-Fehler.
/// </summary>
public sealed class VbaProjectExtractorTests
{
    private readonly VbaProjectExtractor _extractor = new();

    [Fact]
    public void Extract_OoxmlMitMakro_liefertModulQuelltext()
    {
        // Arrange
        var content = ScanCorpus.CreateXlsm(ScanCorpus.CleanSource);

        // Act
        var result = _extractor.Extract(content);

        // Assert
        Assert.True(result.MacroPresent);
        Assert.Equal(1, result.ModuleCount);
        Assert.False(result.EncryptedProject);
        Assert.False(result.ParserError);
        Assert.Contains(result.Modules, m => m.SourceText.Contains("Sub Hello", StringComparison.Ordinal));
    }

    [Fact]
    public void Extract_MakrofreieDatei_liefertMacroPresentFalseOhneFehler()
    {
        // Arrange
        var content = ScanCorpus.CreateMacroFreeXlsm();

        // Act
        var result = _extractor.Extract(content);

        // Assert: makrofreie Dateien sind kein Fehlerzustand (Saga → NichtSignierbar).
        Assert.False(result.MacroPresent);
        Assert.False(result.ParserError);
        Assert.False(result.EncryptedProject);
        Assert.Empty(result.Modules);
    }

    [Fact]
    public void Extract_UngueltigerVbaProjectBlob_liefertParserError()
    {
        // Arrange: vbaProject.bin ist kein CFB-Container.
        var content = ScanCorpus.CreateXlsmWithRawVbaProject([0x00, 0x01, 0x02, 0x03]);

        // Act
        var result = _extractor.Extract(content);

        // Assert
        Assert.True(result.ParserError);
    }

    [Fact]
    public void Extract_VerschluesseltesVbaProjekt_liefertEncryptedProject()
    {
        // Arrange: dir-Stream ist kein valider RLE-Container (AK-45, TC-15).
        var content = ScanCorpus.CreateEncryptedVbaXlsm();

        // Act
        var result = _extractor.Extract(content);

        // Assert
        Assert.True(result.EncryptedProject);
        Assert.False(result.ParserError);
    }

    [Fact]
    public void Extract_MehrereModule_liefertModuleCountUndAlleQuelltexte()
    {
        // Arrange
        var content = ScanCorpus.CreateXlsm(ScanCorpus.CleanSource, """
            Attribute VB_Name = "Module2"
            Sub AutoOpen()
            End Sub
            """);

        // Act
        var result = _extractor.Extract(content);

        // Assert
        Assert.True(result.MacroPresent);
        Assert.Equal(2, result.ModuleCount);
        Assert.Equal(2, result.Modules.Count);
    }
}
