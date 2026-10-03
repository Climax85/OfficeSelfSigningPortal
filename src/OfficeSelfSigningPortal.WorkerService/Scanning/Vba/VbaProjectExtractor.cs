using System.IO.Compression;
using System.Text;
using OpenMcdf;

namespace OfficeSelfSigningPortal.WorkerService.Scanning.Vba;

/// <summary>Extrahiertes VBA-Modul.</summary>
/// <param name="Name">Modulname (aus PROJECT-Stream).</param>
/// <param name="SourceText">Dekomprimierter Modul-Quelltext.</param>
public sealed record VbaModule(string Name, string SourceText);

/// <summary>Ergebnis der VBA-Projekt-Extraktion.</summary>
/// <param name="MacroPresent">True ⇒ VBA-Projekt mit mindestens einem Modul-Stream.</param>
/// <param name="ModuleCount">Anzahl der Modul-Streams im VBA-Speicher.</param>
/// <param name="Modules">Module mit lesbarem Quelltext (kann kleiner als ModuleCount sein).</param>
/// <param name="EncryptedProject">dir-Stream nicht als RLE lesbar → verschlüsseltes/geschütztes Projekt (AK-45).</param>
/// <param name="ParserError">Container-Struktur unverständlich (weder CFB noch OOXML bzw. beschädigter CFB).</param>
public sealed record VbaExtraction(
    bool MacroPresent,
    int ModuleCount,
    IReadOnlyList<VbaModule> Modules,
    bool EncryptedProject,
    bool ParserError);

/// <summary>
/// Extraktion von VBA-Projekten aus OOXML-Makrodateien (Zip → xl|word|ppt/vbaProject.bin,
/// selbst wieder CFB) bzw. direkt aus CFB-OLE-Dateien (OpenMcdf). Modul-Quelltexte werden
/// aus den Modul-Streams MS-OVBA-RLE-dekodiert (Suchposition der CompressedContainer-
/// Signatur 0x01, erste plausibel dekomprimierende Position — der autoritative
/// MODULEOFFSET aus dem dir-Stream ist Kalibrierungs-Backlog).
/// </summary>
public sealed class VbaProjectExtractor
{
    private static readonly byte[] CfbMagic = [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];

    private static readonly string[] VbaStoragePath = ["VBA"];
    private static readonly string[] LegacyVbaStoragePath = ["Macros", "VBA"];

    private static readonly HashSet<string> NonModuleStreams = new(StringComparer.OrdinalIgnoreCase)
    {
        "dir", "_VBA_PROJECT",
    };

    public VbaExtraction Extract(byte[] fileContent)
    {
        ArgumentNullException.ThrowIfNull(fileContent);

        byte[]? cfbContent;
        if (fileContent.AsSpan().StartsWith(CfbMagic))
        {
            cfbContent = fileContent;
        }
        else
        {
            cfbContent = TryExtractVbaProjectFromZip(fileContent, out var zipInvalid);
            if (zipInvalid)
            {
                return new VbaExtraction(false, 0, [], ParserError: true, EncryptedProject: false);
            }

            if (cfbContent is null)
            {
                // Makrofreie Datei — kein Fehlerzustand (Saga führt auf NichtSignierbar).
                return new VbaExtraction(false, 0, [], ParserError: false, EncryptedProject: false);
            }
        }

        return ExtractFromCompoundFile(cfbContent);
    }

    private static byte[]? TryExtractVbaProjectFromZip(byte[] content, out bool invalidZip)
    {
        invalidZip = false;
        try
        {
            using var stream = new MemoryStream(content, writable: false);
            using var zip = new ZipArchive(stream, ZipArchiveMode.Read, leaveOpen: false);
            var entry = zip.Entries.FirstOrDefault(e =>
                e.FullName.EndsWith("/vbaProject.bin", StringComparison.OrdinalIgnoreCase)
                || e.FullName.Equals("vbaProject.bin", StringComparison.OrdinalIgnoreCase));
            if (entry is null)
            {
                return null;
            }

            using var entryStream = entry.Open();
            using var buffer = new MemoryStream();
            entryStream.CopyTo(buffer);
            return buffer.ToArray();
        }
        catch (InvalidDataException)
        {
            invalidZip = true;
            return null;
        }
    }

    private static VbaExtraction ExtractFromCompoundFile(byte[] cfbContent)
    {
        RootStorage compound;
        try
        {
            // OpenMcdf 3.x: CompoundFile ctor → RootStorage.Open(Stream, StorageModeFlags.None);
            // 3.x wirft bei nicht-CFB-Bytes u. a. EndOfStreamException (IOException-Subklasse) statt
            // CFFileFormatException — IOException-Fang bleibt der gemeinsame Pfad.
            compound = RootStorage.Open(new MemoryStream(cfbContent, writable: false), StorageModeFlags.None);
        }
        catch (Exception ex) when (ex is FileFormatException or IOException or ArgumentException)
        {
            return new VbaExtraction(false, 0, [], ParserError: true, EncryptedProject: false);
        }

        using (compound)
        {
            var vbaStorage = ResolveStorage(compound, VbaStoragePath)
                ?? ResolveStorage(compound, LegacyVbaStoragePath);
            if (vbaStorage is null)
            {
                return new VbaExtraction(false, 0, [], ParserError: false, EncryptedProject: false);
            }

            var moduleStreams = ListModuleStreams(vbaStorage);
            if (moduleStreams.Count == 0)
            {
                return new VbaExtraction(false, 0, [], ParserError: false, EncryptedProject: false);
            }

            // dir-Stream als RLE lesbar = unverschlüsseltes Projekt. Ein vorhandenes
            // VBA-Projekt mit unlesbarem dir-Stream gilt als verschlüsselt/geschützt (AK-45).
            if (!TryReadDirStream(vbaStorage))
            {
                return new VbaExtraction(true, moduleStreams.Count, [], ParserError: false, EncryptedProject: true);
            }

            var modules = new List<VbaModule>();
            foreach (var (name, data) in moduleStreams)
            {
                var source = TryDecompressModuleSource(data);
                if (source is not null)
                {
                    modules.Add(new VbaModule(name, source));
                }
            }

            var parserError = modules.Count == 0;
            return new VbaExtraction(true, moduleStreams.Count, modules, ParserError: parserError, EncryptedProject: false);
        }
    }

    private static Storage? ResolveStorage(Storage root, string[] path)
    {
        Storage? current = root;
        foreach (var name in path)
        {
            if (current is null)
            {
                return null;
            }

            current = current.TryOpenStorage(name, out var next) ? next : null;
        }

        return current;
    }

    private static List<(string Name, byte[] Data)> ListModuleStreams(Storage vbaStorage)
    {
        var result = new List<(string, byte[])>();
        // OpenMcdf 3.x: VisitEntries(Action<CFItem>, recursive) → EnumerateEntries() (immer
        // nicht-rekursiv; bei Bedarf offen storage.OpenStorage(entry.Name) selbst aufrufen).
        foreach (var entry in vbaStorage.EnumerateEntries())
        {
            if (entry.Type != EntryType.Stream || NonModuleStreams.Contains(entry.Name))
            {
                continue;
            }

            // CFItemNotFound (2.4.1: Stream zwischen VisitEntries und GetStream verschwunden)
            // hat in 3.x kein direktes Äquivalent — FileFormatException (Storage-Konsistenz) ist
            // der nächstliegende Fehlerpfad.
            try
            {
                using var stream = vbaStorage.OpenStream(entry.Name);
                using var memory = new MemoryStream();
                stream.CopyTo(memory);
                result.Add((entry.Name, memory.ToArray()));
            }
            catch (FileFormatException)
            {
                // Stream-Konsistenzfehler zwischen EnumerateEntries und OpenStream — ignorieren.
            }
        }

        return result;
    }

    private static bool TryReadDirStream(Storage vbaStorage)
    {
        if (!vbaStorage.TryOpenStream("dir", out var dirStream))
        {
            return false;
        }

        try
        {
            using var streamRef = dirStream!;
            using var memory = new MemoryStream();
            streamRef.CopyTo(memory);
            VbaRle.Decompress(memory.ToArray());
            return true;
        }
        catch (InvalidDataException)
        {
            return false;
        }
    }

    /// <summary>
    /// Sucht die CompressedContainer-Signatur 0x01 im Modul-Stream und dekodiert die
    /// erste Position, deren Chunk-Struktur valide und deren Ergebnis plausibler
    /// VBA-Text ist (PerformanceCache-Prefix vor dem eigentlichen Container).
    /// </summary>
    private static string? TryDecompressModuleSource(byte[] streamData)
    {
        for (var offset = 0; offset < streamData.Length - 1; offset++)
        {
            if (streamData[offset] != VbaRle.ContainerSignature)
            {
                continue;
            }

            try
            {
                var decompressed = VbaRle.Decompress(streamData.AsSpan(offset));
                if (decompressed.Length == 0)
                {
                    continue;
                }

                var text = Encoding.ASCII.GetString(decompressed);
                if (IsPlausibleVbaSource(text))
                {
                    return text;
                }
            }
            catch (InvalidDataException)
            {
                // Kein valider Container an dieser Position — weitersuchen.
            }
        }

        return null;
    }

    private static bool IsPlausibleVbaSource(string text)
    {
        var printable = 0;
        var checkedChars = Math.Min(text.Length, 512);
        if (checkedChars == 0)
        {
            return false;
        }

        for (var i = 0; i < checkedChars; i++)
        {
            var c = text[i];
            if (c is >= ' ' and <= '~' or '\r' or '\n' or '\t')
            {
                printable++;
            }
        }

        return (double)printable / checkedChars >= 0.9;
    }
}
