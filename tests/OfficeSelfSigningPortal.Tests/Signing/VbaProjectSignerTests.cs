using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Xml.Linq;
using OfficeSelfSigningPortal.SigningService.Signing;
using OfficeSelfSigningPortal.TestSupport;

namespace OfficeSelfSigningPortal.Tests.Signing;

/// <summary>
/// VbaProjectSigner (AK-50, TC-33 c): Signierung des Sign-Korpus mit einem In-Memory-
/// Selbstsignaturzertifikat; die Ausgabe wird gegen den MS-OVBA-Contents-Hash verifiziert
/// (SignedCms-Signaturprüfung + Bindungs-Digest), Package-Struktur (Signature-Part,
/// Relationship, [Content_Types].xml) geprüft — für .xlsm/.docm/.pptm-Layout.
/// </summary>
public sealed class VbaProjectSignerTests
{
    [Fact]
    public async Task SignAsync_xlsm_erzeugt_verifizierbare_V3_Signatur()
    {
        // Arrange
        using var certificate = CreateCodeSigningCertificate();
        var document = SignCorpus.CreateOoxmlMacroFile(SignCorpus.BuildVbaProject());
        var vbaProjectBefore = ExtractPart(document, "xl/vbaProject.bin");
        var signer = new VbaProjectSigner();

        // Act
        using var stream = CreateExpandable(document);
        var result = await signer.SignAsync(stream, certificate, CancellationToken.None);

        // Assert: Erfolg und Stream wurde ersetzt
        Assert.True(result.Success);
        Assert.Null(result.ErrorCode);
        var signed = stream.ToArray();
        Assert.NotEqual(document, signed);

        // Assert: Signature-Part vorhanden und als DigSigInfoSerialized strukturiert
        var signaturePart = ExtractPart(signed, "xl/vbaProjectSignatureV3.bin");
        var signatureLength = BitConverter.ToUInt32(signaturePart, 0);
        Assert.True(signatureLength > 0);
        Assert.True(36 + signatureLength < signaturePart.Length);
        var cmsDer = signaturePart.AsSpan(36, (int)signatureLength).ToArray();

        // Assert: CMS verifiziert und ist an den V3-Contents-Hash gebunden
        var signedCms = new SignedCms();
        signedCms.Decode(cmsDer);
        signedCms.CheckSignature(verifySignatureOnly: true);

        Assert.Equal("1.3.6.1.4.1.311.2.1.4", signedCms.ContentInfo.ContentType.Value);
        var eContent = signedCms.ContentInfo.Content;
        Assert.Equal((byte)0x30, eContent[0]);
        var boundDigest = eContent[^32..];
        var expectedDigest = VbaContentHasher.ComputeV3ContentHash(vbaProjectBefore);
        Assert.Equal(expectedDigest, boundDigest); // Verifizierung gegen MS-OVBA-Contents-Hash

        // Assert: Relationship und Content-Types gepflegt
        var rels = Encoding.UTF8.GetString(ExtractPart(signed, "xl/_rels/vbaProject.bin.rels"));
        Assert.Contains("relationships/vbaProjectSignature", rels);
        Assert.Contains("vbaProjectSignatureV3.bin", rels);

        var contentTypes = Encoding.UTF8.GetString(ExtractPart(signed, "[Content_Types].xml"));
        Assert.Contains("vbaProject", contentTypes); // Default-Extension "bin" bleibt ausreichend

        // Assert: Original-Part unverändert
        Assert.Equal(vbaProjectBefore, ExtractPart(signed, "xl/vbaProject.bin"));
    }

    [Theory]
    [InlineData("word")]
    [InlineData("ppt")]
    public async Task SignAsync_docm_und_pptm_Layout_wird_einheitlich_signiert(string partFolder)
    {
        // Arrange
        using var certificate = CreateCodeSigningCertificate();
        var document = Relayout(SignCorpus.CreateOoxmlMacroFile(SignCorpus.BuildVbaProject()), partFolder);
        var signer = new VbaProjectSigner();

        // Act
        using var stream = CreateExpandable(document);
        var result = await signer.SignAsync(stream, certificate, CancellationToken.None);

        // Assert
        Assert.True(result.Success);
        var signed = stream.ToArray();
        var signaturePart = ExtractPart(signed, $"{partFolder}/vbaProjectSignatureV3.bin");
        var signatureLength = BitConverter.ToUInt32(signaturePart, 0);
        var cmsDer = signaturePart.AsSpan(36, (int)signatureLength).ToArray();
        var signedCms = new SignedCms();
        signedCms.Decode(cmsDer);
        signedCms.CheckSignature(verifySignatureOnly: true);
    }

    [Fact]
    public async Task SignAsync_erneute_Signierung_ersetzt_den_Signaturpart()
    {
        // Arrange
        using var certificate = CreateCodeSigningCertificate();
        var signer = new VbaProjectSigner();
        using var stream = CreateExpandable(SignCorpus.CreateOoxmlMacroFile(SignCorpus.BuildVbaProject()));
        var first = await signer.SignAsync(stream, certificate, CancellationToken.None);
        Assert.True(first.Success);

        // Act
        var second = await signer.SignAsync(stream, certificate, CancellationToken.None);

        // Assert: nur ein Signature-Part, Signatur weiterhin gültig
        Assert.True(second.Success);
        var signed = stream.ToArray();
        var signatureParts = ListParts(signed).Count(n => n.Contains("vbaProjectSignatureV3", StringComparison.Ordinal));
        Assert.Equal(1, signatureParts);
        var rels = Encoding.UTF8.GetString(ExtractPart(signed, "xl/_rels/vbaProject.bin.rels"));
        Assert.Equal(1, CountOccurrences(rels, "relationships/vbaProjectSignature"));
    }

    [Fact]
    public async Task SignAsync_ohne_vbaProject_schlägt_fehl_ohne_Signatur()
    {
        // Arrange
        using var certificate = CreateCodeSigningCertificate();
        var signer = new VbaProjectSigner();
        using var stream = CreateExpandable(ScanCorpus.CreateMacroFreeXlsm());

        // Act
        var result = await signer.SignAsync(stream, certificate, CancellationToken.None);

        // Assert
        Assert.False(result.Success);
        Assert.Equal("vba-project-invalid", result.ErrorCode);
        Assert.Equal(ScanCorpus.CreateMacroFreeXlsm(), stream.ToArray());
    }

    [Fact]
    public async Task SignAsync_ohne_privaten_Schlüssel_schlägt_fehl()
    {
        // Arrange
        using var certificate = CreateCodeSigningCertificate();
        using var publicOnly = X509CertificateLoader.LoadCertificate(certificate.Export(X509ContentType.Cert));
        var signer = new VbaProjectSigner();
        using var stream = CreateExpandable(SignCorpus.CreateOoxmlMacroFile(SignCorpus.BuildVbaProject()));

        // Act
        var result = await signer.SignAsync(stream, publicOnly, CancellationToken.None);

        // Assert
        Assert.False(result.Success);
        Assert.Equal("certificate-without-private-key", result.ErrorCode);
    }

    private static int CountOccurrences(string text, string value)
    {
        var count = 0;
        var index = 0;
        while ((index = text.IndexOf(value, index, StringComparison.Ordinal)) >= 0)
        {
            count++;
            index += value.Length;
        }

        return count;
    }

    internal static MemoryStream CreateExpandable(byte[] content)
    {
        var stream = new MemoryStream();
        stream.Write(content);
        stream.Position = 0;
        return stream;
    }

    internal static X509Certificate2 CreateCodeSigningCertificate()
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest(
            "CN=OSSP Signing Test",
            rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, critical: true));
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
            [new Oid("1.3.6.1.5.5.7.3.3")], // Code Signing
            critical: false));
        var certificate = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddDays(30));
        // Expliziter PKCS#12-Reimport mit EphemeralKeySet: Private-Key-Material bleibt
        // memory-only (gleiche Anforderung wie ICodeSigningKeyProvider, REQ-15).
        return X509CertificateLoader.LoadPkcs12(
            certificate.Export(X509ContentType.Pfx),
            password: null,
            X509KeyStorageFlags.EphemeralKeySet);
    }

    private static byte[] Relayout(byte[] document, string partFolder)
    {
        using var input = new System.IO.Compression.ZipArchive(new MemoryStream(document, writable: false), System.IO.Compression.ZipArchiveMode.Read);
        using var output = new MemoryStream();
        using (var archive = new System.IO.Compression.ZipArchive(output, System.IO.Compression.ZipArchiveMode.Create, leaveOpen: true))
        {
            foreach (var entry in input.Entries)
            {
                var name = entry.FullName.StartsWith("xl/", StringComparison.Ordinal)
                    ? partFolder + entry.FullName.Substring(2)
                    : entry.FullName;
                using var source = entry.Open();
                var target = archive.CreateEntry(name);
                using var destination = target.Open();
                source.CopyTo(destination);
            }
        }

        return output.ToArray();
    }

    private static byte[] ExtractPart(byte[] package, string name)
    {
        using var archive = new System.IO.Compression.ZipArchive(new MemoryStream(package, writable: false), System.IO.Compression.ZipArchiveMode.Read);
        var entry = archive.GetEntry(name) ?? throw new InvalidOperationException($"Part {name} fehlt.");
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
}
