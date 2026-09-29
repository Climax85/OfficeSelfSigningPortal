using System.Security.Cryptography;
using OfficeSelfSigningPortal.SigningService.Signing;
using OfficeSelfSigningPortal.TestSupport;

namespace OfficeSelfSigningPortal.Tests.Signing;

/// <summary>
/// V3-Contents-Hash (MS-OVBA 2.4.2.7): Der Digest des Sign-Korpus ist als Golden Value
/// gepinnt und wurde unabhängig mit der Python-Referenzimplementation
/// (tools/reference/v3hash_reference.py, direkt aus dem Spec-Pseudocode mit anderem
/// Parser-Stack) ermittelt — beide Implementierungen müssen byte-für-byte übereinstimmen
/// (AK-51, TC-33 Digest-Teil). Der Arena-Korpus (reale Drittprodukt-Datei, nicht
/// Office-konforme Referenz-Records) dient als Smoke-Test ohne Golden Value.
/// </summary>
public sealed class VbaContentHasherTests
{
    // Ermittelt via tools/reference/v3hash_reference.py über examples-temp/signcorpus.xlsm
    // (SignCorpus.BuildVbaProject()); transcript-length = 3407 (content=1104, project=2303).
    private const string SignCorpusDigest =
        "f5495450c2aabc60f8f8d7b6d2b8c0f9d2c3a10876bb9e7e9cfed4b3bdefd0d8";

    [Fact]
    public void ComputeV3ContentHash_SignKorpus_stimmt_mit_Referenz_uerein()
    {
        // Arrange
        var vbaProject = SignCorpus.BuildVbaProject();

        // Act
        var digest = VbaContentHasher.ComputeV3ContentHash(vbaProject);

        // Assert
        Assert.Equal(SignCorpusDigest, Convert.ToHexString(digest).ToLowerInvariant());
    }

    [Fact]
    public void ComputeV3ContentHash_ist_deterministisch()
    {
        // Arrange
        var vbaProject = SignCorpus.BuildVbaProject();

        // Act
        var first = VbaContentHasher.ComputeV3ContentHash(vbaProject);
        var second = VbaContentHasher.ComputeV3ContentHash(vbaProject);

        // Assert
        Assert.Equal(first, second);
    }

    [Fact]
    public void ComputeV3ContentHash_ArenaKorpus_nicht_konforme_Datei_wird_abgelehnt()
    {
        // Arrange: reale Drittprodukt-Datei mit nicht Office-konformen
        // REFERENCEREGISTERED-Records (Libid mit doppeltem Längenpräfix) — ein VBA-Projekt,
        // dessen dir-Stream nicht spec-konform parsebar ist, darf nicht still signiert werden.
        var document = File.ReadAllBytes(Path.Combine(RepoRoot(), "examples", "version-1-3-arena.xlsm"));
        var vbaProject = ExtractVbaProject(document);

        // Act + Assert
        Assert.Throws<InvalidDataException>(() => VbaContentHasher.ComputeV3ContentHash(vbaProject));
    }

    private static byte[] ExtractVbaProject(byte[] document)
    {
        using var archive = new System.IO.Compression.ZipArchive(new MemoryStream(document));
        var entry = archive.Entries.Single(e => e.FullName.EndsWith("/vbaProject.bin", StringComparison.Ordinal));
        using var stream = entry.Open();
        using var memory = new MemoryStream();
        stream.CopyTo(memory);
        return memory.ToArray();
    }

    private static string RepoRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "OfficeSelfSigningPortal.slnx")))
        {
            directory = directory.Parent;
        }

        return directory?.FullName
            ?? throw new InvalidOperationException("Repo-Wurzel (OfficeSelfSigningPortal.slnx) nicht gefunden.");
    }
}
