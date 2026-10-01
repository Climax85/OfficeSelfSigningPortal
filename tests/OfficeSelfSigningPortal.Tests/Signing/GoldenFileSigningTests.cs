using System.Security.Cryptography.Pkcs;
using OfficeSelfSigningPortal.SigningService.Signing;

namespace OfficeSelfSigningPortal.Tests.Signing;

/// <summary>
/// Golden-File-Verifikation (AK-51, TC-33): Die mit Office/signierten Fixtures
/// (examples/golden/README.md, manueller Vorlauf) werden gegen den eigenen VbaProjectSigner
/// laufen gelassen. Das Fixture pinnt den Digest selbst: Office hat beim Signieren seinen
/// eigenen V3-Contents-Hash in die Signatur eingebettet — der Test extrahiert ihn und
/// vergleicht Byte für Byte mit VbaContentHasher.ComputeV3ContentHash (keine Konstanten
/// nötig). Anschließend signiert VbaProjectSigner das Dokument erneut; die erzeugte
/// Signatur muss sich ebenso gegen den MS-OVBA-Contents-Hash verifizieren lassen.
/// Die Selbstsignatur der Fixtures macht die Signaturprüfung maschinenunabhängig
/// (verifySignatureOnly, keine Kette — die Kette wird nicht Teil des Vergleichs).
/// </summary>
public sealed class GoldenFileSigningTests
{
    [Theory]
    [InlineData("golden.xlsm", "xl")]
    [InlineData("golden.docm", "word")]
    [InlineData("golden.pptm", "ppt")]
    public void Office_signierte_Fixtures_digest_Vergleich_und_contents_hash_verifikation(string fixtureName, string partFolder)
    {
        // Arrange
        var document = File.ReadAllBytes(Path.Combine(RepoRoot(), "examples", "golden", fixtureName));
        var vbaProject = ExtractPart(document, $"{partFolder}/vbaProject.bin");
        var signaturePart = ExtractPart(document, $"{partFolder}/vbaProjectSignatureV3.bin");

        // Act: CMS-DER aus der DigSigInfoSerialized der Fixture extrahieren und prüfen
        var cmsDer = ExtractCmsDer(signaturePart);
        var signedCms = new SignedCms();
        signedCms.Decode(cmsDer);
        signedCms.CheckSignature(verifySignatureOnly: true);

        // Assert: Office-Signatur ist an ihren eigenen V3-Contents-Hash gebunden
        Assert.Equal("1.3.6.1.4.1.311.2.1.4", signedCms.ContentInfo.ContentType.Value);
        Assert.Equal((byte)0x30, signedCms.ContentInfo.Content[0]);
        var officeDigest = signedCms.ContentInfo.Content[^32..];
        var ownDigest = VbaContentHasher.ComputeV3ContentHash(vbaProject);
        Assert.Equal(officeDigest, ownDigest); // Byte-für-Byte-Digest-Vergleich (AK-51)
    }

    [Theory]
    [InlineData("golden.xlsm", "xl")]
    [InlineData("golden.docm", "word")]
    [InlineData("golden.pptm", "ppt")]
    public async Task VbaProjectSigner_signiert_Fixtures_erneut_und_Signatur_bleibt_verifizierbar(string fixtureName, string partFolder)
    {
        // Arrange
        var document = File.ReadAllBytes(Path.Combine(RepoRoot(), "examples", "golden", fixtureName));
        using var certificate = VbaProjectSignerTests.CreateCodeSigningCertificate();
        var signer = new VbaProjectSigner();

        // Act: Das reale Office-Paket wird erneut signiert (TC-33)
        using var stream = VbaProjectSignerTests.CreateExpandable(document);
        var result = await signer.SignAsync(stream, certificate, CancellationToken.None);

        // Assert
        Assert.True(result.Success);
        Assert.Null(result.ErrorCode);
        var signed = stream.ToArray();
        var cmsDer = ExtractCmsDer(ExtractPart(signed, $"{partFolder}/vbaProjectSignatureV3.bin"));
        var signedCms = new SignedCms();
        signedCms.Decode(cmsDer);
        signedCms.CheckSignature(verifySignatureOnly: true);

        var boundDigest = signedCms.ContentInfo.Content[^32..];
        var expectedDigest = VbaContentHasher.ComputeV3ContentHash(ExtractPart(signed, $"{partFolder}/vbaProject.bin"));
        Assert.Equal(expectedDigest, boundDigest); // Bindung an den MS-OVBA-Contents-Hash

        var signatureParts = ListParts(signed).Count(n => n.Contains("vbaProjectSignatureV3", StringComparison.Ordinal));
        Assert.Equal(1, signatureParts);
    }

    /// <summary>DigSigInfoSerialized (MS-OSHARED §2.3.2.1): 36-Byte-Offset-Header, cbSignature zuerst.</summary>
    private static byte[] ExtractCmsDer(byte[] signaturePart)
    {
        var cbSignature = BitConverter.ToUInt32(signaturePart, 0);
        Assert.True(cbSignature > 0);
        Assert.True(36 + cbSignature <= signaturePart.Length);
        return signaturePart.AsSpan(36, (int)cbSignature).ToArray();
    }

    private static byte[] ExtractPart(byte[] package, string name)
    {
        using var archive = new System.IO.Compression.ZipArchive(new MemoryStream(package, writable: false), System.IO.Compression.ZipArchiveMode.Read);
        var entry = archive.GetEntry(name) ?? throw new InvalidOperationException($"Part {name} fehlt im Fixture.");
        using var stream = entry.Open();
        using var memory = new MemoryStream();
        stream.CopyTo(memory);
        return memory.ToArray();
    }

    private static IReadOnlyList<string> ListParts(byte[] package)
    {
        using var archive = new System.IO.Compression.ZipArchive(new MemoryStream(package, writable: false), System.IO.Compression.ZipArchiveMode.Read);
        return archive.Entries.Select(e => e.FullName).ToList();
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
