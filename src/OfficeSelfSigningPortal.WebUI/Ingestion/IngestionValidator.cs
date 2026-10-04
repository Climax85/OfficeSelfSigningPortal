using System.IO.Compression;
using System.Security.Cryptography;
using Ossp.Vba;

namespace OfficeSelfSigningPortal.WebUI.Ingestion;

using static IngestionVerdict;

/// <summary>
/// Strikte Vorprüfung eines Uploads vor der Scanner-Übergabe (REQ-10, REQ-23, TM-13).
/// Reine Funktion über dem Blob — alle Prüfungen arbeiten auf ZIP-Zentralverzeichnis-
/// Einträgen (deklarierte Größen) und Signaturen, ohne Paketinhalte zu dekomprimieren.
/// </summary>
public static class IngestionValidator
{
    private static readonly Dictionary<string, (string RootPart, string VbaProject)> PackageLayout = new(StringComparer.Ordinal)
    {
        ["xlsm"] = ("xl/workbook.xml", "xl/vbaProject.bin"),
        ["docm"] = ("word/document.xml", "word/vbaProject.bin"),
        ["pptm"] = ("ppt/presentation.xml", "ppt/vbaProject.bin"),
    };

    public static IngestionVerdict Validate(string originalFileName, byte[] content, IngestionOptions options)
    {
        var extension = Path.GetExtension(originalFileName).TrimStart('.');

        // 1. Format (TC-02): nur .xlsm/.docm/.pptm.
        if (string.IsNullOrEmpty(extension) ||
            !options.AllowedExtensions.TryGetValue(extension, out var contentType))
        {
            return new Rejected(
                "format",
                $"Format nicht erlaubt: zugelassen sind ausschließlich .xlsm, .docm und .pptm.");
        }

        // 2. Größe (TC-03/AK-37): exaktes Limit, 1 Byte darüber wird abgelehnt.
        if (content.LongLength > options.MaxFileSizeBytes)
        {
            return new Rejected(
                "size-limit",
                $"Größenlimit überschritten: maximal {options.MaxFileSizeBytes / (1024 * 1024)} MB pro Datei.");
        }

        // 3./4. Polyglot (TC-08) bzw. Korruption (TC-05): CFB-Header mit lesbarem
        // ZIP-Layer ist ein OLE/ZIP-Polyglot und wird vor der Scanner-Übergabe abgelehnt.
        var hasCfbHeader = content.AsSpan(0, Math.Min(content.Length, VbaRle.CfbMagic.Length)).SequenceEqual(VbaRle.CfbMagic);
        var archive = TryOpenZip(content);

        if (hasCfbHeader)
        {
            return archive is not null
                ? new Rejected("polyglot", "Ablehnung: Datei mit OLE- und ZIP-Layout (Polyglot) ist nicht zugelassen.")
                : new Corrupt("Ungültige OLE-Struktur: Datei ist kein lesbares OOXML-Paket.");
        }

        if (archive is null)
        {
            return new Corrupt("Ungültige ZIP-Struktur: Datei ist kein lesbares OOXML-Paket.");
        }

        using (archive)
        {
            // 5. Passwortschutz (TC-04): Agile Encryption (EncryptionInfo + EncryptedPackage).
            if (archive.GetEntry("EncryptionInfo") is not null && archive.GetEntry("EncryptedPackage") is not null)
            {
                return new Rejected(
                    "password-protected",
                    "Passwortgeschützte Dateien sind nicht zugelassen: bitte Schutz aufheben und erneut einreichen.");
            }

            // 6. Zip-Bomb (TC-07): extremes Kompressionsverhältnis anhand der deklarierten
            // Größen (keine Dekompression — Schutz vor Ressourcenexhaustion, TM-13).
            long totalUncompressed = 0;
            long totalCompressed = 0;
            foreach (var entry in archive.Entries)
            {
                totalUncompressed += entry.Length;
                totalCompressed += entry.CompressedLength;
            }

            var ratio = totalCompressed == 0 ? 0.0 : totalUncompressed / (double)totalCompressed;
            if (totalUncompressed > options.MaxDecompressedTotalBytes || ratio > options.MaxCompressionRatio)
            {
                return new Rejected(
                    "zip-bomb",
                    $"Zip-Bomb-Muster erkannt (Kompressionsverhältnis {ratio:F0}:1, deklariert {totalUncompressed / (1024 * 1024)} MB entpackt).");
            }

            // 7. OOXML-Grundstruktur (TC-05): Pflicht-Root-Part je Dateityp.
            var layout = PackageLayout[contentType];
            if (archive.GetEntry(layout.RootPart) is null)
            {
                return new Corrupt($"OOXML-Grundstruktur unvollständig: '{layout.RootPart}' fehlt.");
            }

            // 8. Makro-Präsenz (TC-06): ohne VBA-Projekt ist nichts zu signieren.
            if (archive.GetEntry(layout.VbaProject) is null)
            {
                return new MacroFree();
            }
        }

        // 9. Gültiger Upload — TOCTOU-Basis für Scan und Signierung (TM-03/TM-19).
        return new Accepted(contentType, Convert.ToHexString(SHA256.HashData(content)));
    }

    private static ZipArchive? TryOpenZip(byte[] content)
    {
        try
        {
            return new ZipArchive(new MemoryStream(content, writable: false), ZipArchiveMode.Read);
        }
        catch (InvalidDataException)
        {
            return null;
        }
    }
}
