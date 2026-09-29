using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Xml.Linq;

namespace OfficeSelfSigningPortal.SigningService.Signing;

/// <summary>
/// Erzeugt den <c>vbaProjectSignatureV3.bin</c>-Part (MS-OSHARED DigSigInfoSerialized)
/// und aktualisiert das OOXML-Paket (Part + Relationship + [Content_Types].xml).
/// Das Byte-Layout folgt EPPlus (ExcelVBASignature/CertUtil/ProjectSignUtil) — der
/// interop-erprobten Referenzimplementierung: Die eingebettete SpcIndirectDataContent-
/// Struktur wird von Office nicht streng-DER geparst (Offset-Felder in SigDataV1Serialized),
/// die teils hartkodierten Längen werden daher bewusst 1:1 übernommen.
/// </summary>
public sealed class VbaProjectSigner : Ossp.Contracts.IVbaProjectSigner
{
    public const string VbaProjectPartSuffix = "/vbaProject.bin";
    public const string SignaturePartName = "vbaProjectSignatureV3.bin";

    private const string VbaProjectSignatureRelationshipType =
        "http://schemas.microsoft.com/office/2006/relationships/vbaProjectSignature";

    private const string V3SignatureContentType = "application/vnd.ms-office.vbaProjectSignatureV3";

    private const string PackageContentTypesNamespace =
        "http://schemas.openxmlformats.org/package/2006/content-types";

    private const string PackageRelationshipsNamespace =
        "http://schemas.openxmlformats.org/package/2006/relationships";

    /// <summary>
    /// Signiert das VBA-Projekt des OOXML-Dokuments in-place: Der <paramref name="document"/>-
    /// Stream wird bei Erfolg vollständig durch das signierte Paket ersetzt.
    /// </summary>
    public async Task<Ossp.Contracts.SignResult> SignAsync(
        Stream document, X509Certificate2 certificate, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(document);
        ArgumentNullException.ThrowIfNull(certificate);

        if (!certificate.HasPrivateKey)
        {
            return new Ossp.Contracts.SignResult(false, "certificate-without-private-key");
        }

        ct.ThrowIfCancellationRequested();

        byte[] package;
        try
        {
            package = await ReadAllBytesAsync(document, ct);
        }
        catch (Exception ex) when (ex is IOException or NotSupportedException)
        {
            return new Ossp.Contracts.SignResult(false, "document-not-readable");
        }

        byte[] signedPackage;
        try
        {
            signedPackage = SignPackage(package, certificate);
        }
        catch (InvalidDataException)
        {
            return new Ossp.Contracts.SignResult(false, "vba-project-invalid");
        }

        document.SetLength(0);
        if (document.CanSeek)
        {
            document.Position = 0;
        }

        await document.WriteAsync(signedPackage, ct);
        if (document.CanSeek)
        {
            document.Position = 0;
        }

        return new Ossp.Contracts.SignResult(true, null);
    }

    /// <summary>Transformiert das Paket-Bytes: Hash → SignedCms → DigSigInfoSerialized → ZIP-Update.</summary>
    internal static byte[] SignPackage(byte[] package, X509Certificate2 certificate)
    {
        using var archive = new System.IO.Compression.ZipArchive(
            new MemoryStream(package, writable: false), System.IO.Compression.ZipArchiveMode.Read);

        var vbaProjectEntry = archive.Entries.SingleOrDefault(e =>
            e.FullName.EndsWith(VbaProjectPartSuffix, StringComparison.Ordinal));
        if (vbaProjectEntry is null)
        {
            throw new InvalidDataException("Kein vbaProject.bin-Part im OOXML-Paket gefunden.");
        }

        var vbaProjectPartFolder = vbaProjectEntry.FullName[..^VbaProjectPartSuffix.Length];
        var signaturePartFullName = $"{vbaProjectPartFolder}/{SignaturePartName}";
        var relsPartFullName = $"{vbaProjectPartFolder}/_rels/vbaProject.bin.rels";

        using var vbaProjectStream = vbaProjectEntry.Open();
        using var vbaProjectMemory = new MemoryStream();
        vbaProjectStream.CopyTo(vbaProjectMemory);
        var vbaProject = vbaProjectMemory.ToArray();

        var contentHash = VbaContentHasher.ComputeV3ContentHash(vbaProject);
        var signedCmsDer = CreateSignedCms(contentHash, certificate);
        var signaturePart = VbaSignatureBlob.CreateDigSigInfoSerialized(certificate, signedCmsDer);

        // Paket-Teile sammeln (Reihenfolge bleibt stabil), Signatur-/rels-/Content-Types-Parts ersetzen.
        var parts = new List<KeyValuePair<string, byte[]>>();
        foreach (var entry in archive.Entries)
        {
            if (entry.FullName == signaturePartFullName
                || entry.FullName == relsPartFullName
                || entry.FullName == "[Content_Types].xml")
            {
                continue;
            }

            using var entryStream = entry.Open();
            using var entryMemory = new MemoryStream();
            entryStream.CopyTo(entryMemory);
            parts.Add(new KeyValuePair<string, byte[]>(entry.FullName, entryMemory.ToArray()));
        }

        var contentTypes = ReadPart(archive, "[Content_Types].xml");
        parts.Add(new KeyValuePair<string, byte[]>(
            "[Content_Types].xml",
            UpdateContentTypes(contentTypes, vbaProjectPartFolder)));

        var rels = ReadPartOrNull(archive, relsPartFullName);
        parts.Add(new KeyValuePair<string, byte[]>(
            relsPartFullName,
            UpdateVbaProjectRels(rels, SignaturePartName)));

        parts.Add(new KeyValuePair<string, byte[]>(signaturePartFullName, signaturePart));

        using var output = new MemoryStream();
        using (var signedArchive = new System.IO.Compression.ZipArchive(
            output, System.IO.Compression.ZipArchiveMode.Create, leaveOpen: true))
        {
            foreach (var (name, content) in parts)
            {
                var entry = signedArchive.CreateEntry(name);
                using var entryStream = entry.Open();
                entryStream.Write(content, 0, content.Length);
            }
        }

        return output.ToArray();
    }

    /// <summary>
    /// Erzeugt den CMS-signedData-Block (SpcIndirectDataContent als eContent, SHA-256).
    /// </summary>
    internal static byte[] CreateSignedCms(byte[] contentHash, X509Certificate2 certificate)
    {
        var spcIndirectDataContent = VbaSignatureBlob.CreateSpcIndirectDataContent(contentHash);
        var contentInfo = new ContentInfo(new Oid("1.3.6.1.4.1.311.2.1.4"), spcIndirectDataContent);
        var signedCms = new SignedCms(contentInfo);
        var signer = new CmsSigner(certificate)
        {
            DigestAlgorithm = new Oid("2.16.840.1.101.3.4.2.1"), // SHA-256 (REQ-16)
        };
        signedCms.ComputeSignature(signer, silent: false);
        return signedCms.Encode();
    }

    private static byte[] UpdateContentTypes(byte[]? contentTypes, string vbaProjectPartFolder)
    {
        XDocument document;
        if (contentTypes is null)
        {
            document = new XDocument(new XElement(
                XNamespace.Get(PackageContentTypesNamespace) + "Types"));
        }
        else
        {
            document = XDocument.Parse(Encoding.UTF8.GetString(contentTypes).TrimStart('\uFEFF'));
        }

        var ns = XNamespace.Get(PackageContentTypesNamespace);
        var types = document.Root ?? throw new InvalidDataException("[Content_Types].xml ohne Root-Element.");

        // Office deklariert vbaProject*.bin-Parts üblicherweise über die Default-Extension
        // "bin" — dann ist keine Override nötig (EPPlus schreibt alternativ einen Override).
        var hasBinDefault = types.Elements(ns + "Default")
            .Any(e => string.Equals(e.Attribute("Extension")?.Value, "bin", StringComparison.OrdinalIgnoreCase));
        if (hasBinDefault)
        {
            return EncodeDocument(document);
        }

        var partName = $"/{vbaProjectPartFolder}/{SignaturePartName}";
        var existing = types.Elements(ns + "Override")
            .FirstOrDefault(e => string.Equals(e.Attribute("PartName")?.Value, partName, StringComparison.Ordinal));
        if (existing is null)
        {
            types.Add(new XElement(
                ns + "Override",
                new XAttribute("PartName", partName),
                new XAttribute("ContentType", V3SignatureContentType)));
        }

        return EncodeDocument(document);
    }

    private static byte[] UpdateVbaProjectRels(byte[]? rels, string signaturePartName)
    {
        XDocument document;
        if (rels is null)
        {
            document = new XDocument(new XElement(
                XNamespace.Get(PackageRelationshipsNamespace) + "Relationships"));
        }
        else
        {
            document = XDocument.Parse(Encoding.UTF8.GetString(rels).TrimStart('\uFEFF'));
        }

        var ns = XNamespace.Get(PackageRelationshipsNamespace);
        var relationships = document.Root ?? throw new InvalidDataException("vbaProject.bin.rels ohne Root-Element.");

        relationships.Elements(ns + "Relationship")
            .Where(e => string.Equals(
                e.Attribute("Type")?.Value,
                VbaProjectSignatureRelationshipType,
                StringComparison.Ordinal))
            .Remove();

        var nextId = relationships.Elements(ns + "Relationship")
            .Select(e => e.Attribute("Id")?.Value)
            .Where(id => id is not null && id.StartsWith("rId", StringComparison.Ordinal))
            .Select(id => int.TryParse(id!.Substring(3), out var number) ? number : 0)
            .DefaultIfEmpty(0)
            .Max() + 1;

        relationships.Add(new XElement(
            ns + "Relationship",
            new XAttribute("Id", $"rId{nextId}"),
            new XAttribute("Type", VbaProjectSignatureRelationshipType),
            new XAttribute("Target", signaturePartName)));

        return EncodeDocument(document);
    }

    private static byte[] EncodeDocument(XDocument document)
    {
        using var memory = new MemoryStream();
        // BOM-frei: Der Part wird beim erneuten Signieren erneut geparst — ein
        // eingebettetes \uFEFF erzeugt dort einen XML-Parse-Fehler.
        using (var writer = new StreamWriter(memory, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false), bufferSize: 1024, leaveOpen: true))
        {
            document.Save(writer, SaveOptions.None);
        }

        return memory.ToArray();
    }

    private static byte[]? ReadPartOrNull(
        System.IO.Compression.ZipArchive archive, string name)
    {
        var entry = archive.GetEntry(name);
        if (entry is null)
        {
            return null;
        }

        return ReadPart(archive, name);
    }

    private static byte[] ReadPart(System.IO.Compression.ZipArchive archive, string name)
    {
        var entry = archive.GetEntry(name)
            ?? throw new InvalidDataException($"Part '{name}' fehlt im OOXML-Paket.");
        using var stream = entry.Open();
        using var memory = new MemoryStream();
        stream.CopyTo(memory);
        return memory.ToArray();
    }

    private static async Task<byte[]> ReadAllBytesAsync(Stream stream, CancellationToken ct)
    {
        if (stream.CanSeek)
        {
            stream.Position = 0;
        }

        using var memory = new MemoryStream();
        await stream.CopyToAsync(memory, ct);
        return memory.ToArray();
    }
}
