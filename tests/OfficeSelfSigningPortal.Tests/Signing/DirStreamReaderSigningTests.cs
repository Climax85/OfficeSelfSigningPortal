using OfficeSelfSigningPortal.SigningService.Signing;
using OfficeSelfSigningPortal.TestSupport;
using OpenMcdf;
using OpenMcdfVersion = OpenMcdf.Version;

namespace OfficeSelfSigningPortal.Tests.Signing;

/// <summary>
/// Signier-Korpus (TestSupport): spec-valider dir-Stream mit Projekt-/Referenz-
/// (Registered, Control mit/ohne Extended, Original+Control) und Modul-Records
/// (prozedural + Dokument mit Default-Attributen) wird vollständig geparst und die
/// hash-relevanten Felder werden festgehalten (MS-OVBA 2.4.2.5).
/// </summary>
public sealed class DirStreamReaderSigningTests
{
    [Fact]
    public void Parse_SignKorpus_erfasst_alle_hash_relevanten_Felder()
    {
        // Arrange
        var vbaProject = SignCorpus.BuildVbaProject();
        using var compound = RootStorage.Open(new MemoryStream(vbaProject, writable: false), StorageModeFlags.None);
        using var dirStream = compound.TryOpenStorage("VBA", out var vbaStorage)
            ? vbaStorage!.TryOpenStream("dir", out var ds) ? ds! : throw new InvalidDataException("dir stream missing")
            : throw new InvalidDataException("VBA storage missing");
        using var dirMemory = new MemoryStream();
        dirStream.CopyTo(dirMemory);
        var dirCompressed = dirMemory.ToArray();

        // Act
        var dir = DirStreamReader.Parse(VbaRleDecompressor.Decompress(dirCompressed), fallbackCodePage: 1252);

        // Assert: Projekt-Information
        Assert.Equal(1252, dir.CodePage);
        Assert.Equal(4u, dir.SysKindSize);
        Assert.Equal(SignCorpus.Lcid, dir.Lcid);
        Assert.Equal(SignCorpus.Lcid, dir.LcidInvoke);
        Assert.Equal(SignCorpus.ProjectName, System.Text.Encoding.GetEncoding(1252).GetString(dir.ProjectName));
        Assert.Equal(1u, dir.VersionMajor);

        // Assert: Referenzen — Registered, Control mit Extended-Block, Original+Control-Paar
        Assert.Equal(3, dir.References.Count);

        var registered = Assert.Single(dir.References, r => r.RecordId == 0x000D);
        Assert.Equal("stdole", System.Text.Encoding.GetEncoding(1252).GetString(registered.NameRecord.Name));
        Assert.Contains("stdole2.tlb", System.Text.Encoding.GetEncoding(1252).GetString(registered.RegisteredLibid));
        Assert.Equal(0u, registered.RegisteredReserved1);
        Assert.Equal((ushort)0, registered.RegisteredReserved2);

        var control = Assert.Single(dir.References, r => r.RecordId == 0x002F && r.OriginalSizeOfLibid == 0);
        Assert.Equal("ControlLib", System.Text.Encoding.GetEncoding(1252).GetString(control.NameRecord.Name));
        Assert.True(control.ControlHasExtendedBlock);
        Assert.Contains("controllib.ocx", System.Text.Encoding.GetEncoding(1252).GetString(control.ControlLibidTwiddled));
        Assert.Contains("controllib.exd", System.Text.Encoding.GetEncoding(1252).GetString(control.ControlLibidExtended));
        Assert.Equal(16, control.ControlOriginalTypeLib.Length);
        Assert.Equal(0u, control.ControlCookie);

        var originalWithControl = Assert.Single(dir.References, r => r.RecordId == 0x0033);
        Assert.Equal("OrigControl", System.Text.Encoding.GetEncoding(1252).GetString(originalWithControl.NameRecord.Name));
        Assert.StartsWith(@"*\O", System.Text.Encoding.GetEncoding(1252).GetString(originalWithControl.OriginalLibid));
        Assert.StartsWith(@"*\G", System.Text.Encoding.GetEncoding(1252).GetString(originalWithControl.ControlLibidTwiddled));
        Assert.False(originalWithControl.ControlHasExtendedBlock);

        // Assert: Module
        Assert.Equal(2, dir.Modules.Count);
        var standard = Assert.Single(dir.Modules, m => m.StreamName == "CleanModule");
        Assert.True(standard.IsProcedural);
        Assert.False(standard.Private);
        Assert.Equal(0u, standard.TextOffset);

        var document = Assert.Single(dir.Modules, m => m.StreamName == "ThisWorkbook");
        Assert.False(document.IsProcedural);
        Assert.True(document.Private);
        Assert.NotEmpty(document.NameUnicode);
    }
}
