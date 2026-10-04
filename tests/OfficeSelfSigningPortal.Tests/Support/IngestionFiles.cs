using System.Diagnostics;
using System.IO.Compression;
using System.Text;
using Ossp.Vba;

namespace OfficeSelfSigningPortal.Tests.Support;

/// <summary>
/// Erzeugt synthetische OOXML-Makrodateien für Seam S1 (TC-01–TC-08).
/// Die Dateien sind minimale, aber strukturell plausible OOXML-Pakete —
/// die Ingestion prüft in T03 nur Präsenz der Pflicht-Parts, kein VBA-Parsing.
/// </summary>
public static class IngestionFiles
{
    private const string PadEntryName = "docProps/padding.bin";

    // Lokaler Header (30) + zentraler Verzeichniseintrag (46), je plus Name —
    // ein Stored Entry ist damit byte-exakt größenkalkulierbar.
    private const long StoredEntryOverhead = 30 + 19 + 46 + 19; // Name "docProps/padding.bin" (19 Bytes) je Eintrag

    private static readonly Dictionary<string, (string RootPart, string VbaProject)> PackageLayout = new(StringComparer.Ordinal)
    {
        ["xlsm"] = ("xl/workbook.xml", "xl/vbaProject.bin"),
        ["docm"] = ("word/document.xml", "word/vbaProject.bin"),
        ["pptm"] = ("ppt/presentation.xml", "ppt/vbaProject.bin"),
    };

    private const string ContentTypesXml = """
        <?xml version="1.0" encoding="UTF-8" standalone="yes"?>
        <Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
          <Default Extension="bin" ContentType="application/vnd.ms-office.vbaProject"/>
        </Types>
        """;

    private static readonly byte[] VbaProjectPayload = Encoding.UTF8.GetBytes("synthetic-vbaProject-payload");

    public static byte[] CreateValidMacroFile(string contentType) => CreateMacroFile(contentType, storedPaddingBytes: 0);

    /// <summary>
    /// Erzeugt eine gültige Makrodatei mit exakt <paramref name="targetSize"/> Bytes:
    /// Das Padding läuft als Stored Entry (unkomprimiert), damit sind weder das
    /// Kompressionsverhältnis (Zip-Bomb-Schwelle) noch die Struktur betroffen.
    /// Die Entry-Overhead-Bytes werden empirisch nachjustiert (linear in der Pad-Größe).
    /// </summary>
    public static byte[] CreateMacroFileOfSize(string contentType, long targetSize)
    {
        var baseSize = CreateValidMacroFile(contentType).LongLength;
        var initialPad = targetSize - baseSize - StoredEntryOverhead;
        if (initialPad < 0)
        {
            throw new ArgumentException("Zielgröße ist kleiner als das Basispaket.", nameof(targetSize));
        }

        var firstPass = CreateMacroFile(contentType, initialPad);
        var correctedPad = initialPad + (targetSize - firstPass.LongLength);
        if (correctedPad < 0)
        {
            throw new ArgumentException("Zielgröße ist kleiner als das Basispaket.", nameof(targetSize));
        }

        var result = correctedPad == initialPad ? firstPass : CreateMacroFile(contentType, correctedPad);
        Debug.Assert(result.LongLength == targetSize, "Stored-Entry-Padding muss die Zielgröße exakt treffen.");
        return result;
    }

    public static byte[] CreateMacroFile(string contentType, long storedPaddingBytes)
    {
        var (rootPart, vbaProject) = PackageLayout[contentType];
        using var stream = new MemoryStream();
        using (var zip = new ZipArchive(stream, ZipArchiveMode.Create, leaveOpen: true))
        {
            AddEntry(zip, "[Content_Types].xml", ContentTypesXml);
            AddEntry(zip, rootPart, "<xml/>");
            AddEntry(zip, vbaProject, VbaProjectPayload);

            if (storedPaddingBytes > 0)
            {
                var pad = zip.CreateEntry(PadEntryName, CompressionLevel.NoCompression);
                using var padStream = pad.Open();
                var chunk = new byte[81920];
                for (long remaining = storedPaddingBytes; remaining > 0; remaining -= chunk.Length)
                {
                    padStream.Write(chunk, 0, (int)Math.Min(chunk.Length, remaining));
                }
            }
        }

        return stream.ToArray();
    }

    /// <summary>Makrofreie Datei: gültiges OOXML-Paket ohne vbaProject.bin (TC-06).</summary>
    public static byte[] CreateMacroFreeFile(string contentType)
    {
        var (rootPart, _) = PackageLayout[contentType];
        using var stream = new MemoryStream();
        using (var zip = new ZipArchive(stream, ZipArchiveMode.Create, leaveOpen: true))
        {
            AddEntry(zip, "[Content_Types].xml", ContentTypesXml);
            AddEntry(zip, rootPart, "<xml/>");
        }

        return stream.ToArray();
    }

    /// <summary>Passwortgeschützte OOXML-Datei (Agile Encryption: EncryptionInfo + EncryptedPackage).</summary>
    public static byte[] CreatePasswordProtectedFile()
    {
        using var stream = new MemoryStream();
        using (var zip = new ZipArchive(stream, ZipArchiveMode.Create, leaveOpen: true))
        {
            AddEntry(zip, "[Content_Types].xml", ContentTypesXml);
            AddEntry(zip, "EncryptionInfo", "synthetic-encryption-info");
            AddEntry(zip, "EncryptedPackage", "synthetic-encrypted-package");
        }

        return stream.ToArray();
    }

    /// <summary>Polyglot: gültiger CFB-Header (OLE) mit darauffolgendem lesbarem ZIP-Layer.</summary>
    public static byte[] CreatePolyglotFile()
    {
        var zipBytes = CreateValidMacroFile("xlsm");
        var polyglot = new byte[VbaRle.CfbMagic.Length + zipBytes.Length];
        VbaRle.CfbMagic.CopyTo(polyglot, 0);
        zipBytes.CopyTo(polyglot, VbaRle.CfbMagic.Length);
        return polyglot;
    }

    /// <summary>Zip-Bomb-Muster: deklariert <paramref name="declaredUncompressedBytes"/> entpackte Bytes,
    /// übertragen werden nur wenige komprimierte Bytes (Null-Block, extremes Verhältnis).</summary>
    public static byte[] CreateZipBombFile(long declaredUncompressedBytes)
    {
        using var stream = new MemoryStream();
        using (var zip = new ZipArchive(stream, ZipArchiveMode.Create, leaveOpen: true))
        {
            AddEntry(zip, "[Content_Types].xml", ContentTypesXml);
            AddEntry(zip, "xl/workbook.xml", "<xml/>");

            var bomb = zip.CreateEntry("xl/vbaProject.bin", CompressionLevel.SmallestSize);
            using var bombStream = bomb.Open();
            var chunk = new byte[81920];
            for (long remaining = declaredUncompressedBytes; remaining > 0; remaining -= chunk.Length)
            {
                bombStream.Write(chunk, 0, (int)Math.Min(chunk.Length, remaining));
            }
        }

        return stream.ToArray();
    }

    /// <summary>Korrumpierte Datei: entweder Zufallsbytes (kein ZIP) oder CFB-Header ohne ZIP-Layer.</summary>
    public static byte[] CreateCorruptFile(bool cfbHeaderOnly)
    {
        if (cfbHeaderOnly)
        {
            var cfb = new byte[4096];
            VbaRle.CfbMagic.CopyTo(cfb, 0);
            return cfb;
        }

        var random = new byte[4096];
        System.Security.Cryptography.RandomNumberGenerator.Fill(random);
        return random;
    }

    private static void AddEntry(ZipArchive zip, string name, string content)
        => AddEntry(zip, name, Encoding.UTF8.GetBytes(content));

    private static void AddEntry(ZipArchive zip, string name, byte[] content)
    {
        var entry = zip.CreateEntry(name, CompressionLevel.Fastest);
        using var entryStream = entry.Open();
        entryStream.Write(content, 0, content.Length);
    }
}
