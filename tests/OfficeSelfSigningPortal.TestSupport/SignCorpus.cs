using System.Text;
using OpenMcdf;
using OpenMcdfVersion = OpenMcdf.Version;

namespace OfficeSelfSigningPortal.TestSupport;

/// <summary>
/// Vollständiges, spec-valides VBA-Projekt für Signier-Tests (Anhang C, MS-OVBA 2.3/2.4.2.5):
/// PROJECT-Stream mit Header-Properties, Sektionen und Designer-Verweis, dir-Stream mit
/// Projekt-/Referenz-/Modul-Records (inkl. REFERENCECONTROL mit Extended-Block) sowie
/// Modul-Streams (RLE, Quelltext ab Offset 0). Der Aufbau ist fix, damit Hash-Golden-Values
/// deterministisch sind.
/// </summary>
public static class SignCorpus
{
    static SignCorpus()
    {
        // MBCS-Codepage 1252 für Fixture-Erzeugung (siehe VbaContentHasher).
        Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
    }

    public const int CodePage = 1252;
    public const uint Lcid = 0x0409;

    public const string ProjectName = "OsspSignTest";

    /// <summary>Standard-Modul mit VB_Name-Attribut und zwei Prozeduren (CRLF-Zeilenumbrüche).</summary>
    public const string StandardModuleSource =
        "Attribute VB_Name = \"CleanModule\"\r\n" +
        "Option Explicit\r\n" +
        "Sub Hello()\r\n" +
        "    MsgBox \"Hello\"\r\n" +
        "End Sub\r\n";

    /// <summary>Dokumentenmodul mit Default-Attributen (müssen vom Hash ausgeschlossen werden).</summary>
    public const string DocumentModuleSource =
        "Attribute VB_Name = \"ThisWorkbook\"\r\n" +
        "Attribute VB_Base = \"0{00020820-0000-0000-C000-000000000046}\"\r\n" +
        "Attribute VB_GlobalNameSpace = False\r\n" +
        "Attribute VB_Creatable = False\r\n" +
        "Attribute VB_PredeclaredId = True\r\n" +
        "Attribute VB_Exposed = True\r\n" +
        "Attribute VB_TemplateDerived = False\r\n" +
        "Attribute VB_Customizable = True\r\n" +
        "Private Sub Workbook_Open()\r\n" +
        "End Sub\r\n";

    /// <summary>
    /// Baut das CFB-vbaProject.bin: Root mit PROJECT-Stream und VBA-Speicher (dir + Modul-Streams),
    /// optional Designer-Storages (frm*) für BaseClass-Properties.
    /// </summary>
    public static byte[] BuildVbaProject()
    {
        // OpenMcdf 3.x — siehe ScanCorpus.BuildVbaProject für Begründung des Musters
        // (LeaveOpen + expliziter CfbStream-Dispose, sonst leere Streams beim Reopen).
        var output = new MemoryStream();
        using (var compound = RootStorage.Create(output, OpenMcdfVersion.V3, StorageModeFlags.Transacted | StorageModeFlags.LeaveOpen))
        {
            var vba = compound.CreateStorage("VBA");
            WriteStream(vba, "dir", VbaRleCompressor.CompressStoreOnly(BuildDirStream()));

            AddModule(vba, "CleanModule", StandardModuleSource, procedural: true);
            AddModule(vba, "ThisWorkbook", DocumentModuleSource, procedural: false);

            WriteStream(compound, "PROJECT", Encoding.GetEncoding(CodePage).GetBytes(BuildProjectText()));

            var designer = compound.CreateStorage("frmTest");
            WriteStream(designer, "o", new byte[] { 0x10, 0x20, 0x30 });
            WriteStream(designer, "f", Encoding.ASCII.GetBytes("Begin {C62A69F0-16DC-11CE-9E98-00AA00574A4F} frmTest\r\nEnd\r\n"));

            // Siehe ScanCorpus.BuildVbaProject — Transacted-Modus verlangt expliziten Commit.
            compound.Commit();
        }

        return output.ToArray();

        static void WriteStream(OpenMcdf.Storage parent, string name, byte[] data)
        {
            using var stream = parent.CreateStream(name);
            stream.Write(data, 0, data.Length);
            stream.Flush();
        }
    }

    /// <summary>Baut eine OOXML-Makro-Datei um das angegebene vbaProject.bin (xl/word/ppt-Layout).</summary>
    public static byte[] CreateOoxmlMacroFile(byte[] vbaProject, string partFolder = "xl")
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
            AddEntry(zip, $"{partFolder}/vbaProject.bin", vbaProject);
        }

        return package.ToArray();
    }

    private static void AddModule(OpenMcdf.Storage vba, string streamName, string source, bool procedural)
    {
        var compressed = VbaRleCompressor.CompressStoreOnly(Encoding.GetEncoding(CodePage).GetBytes(source));
        using var module = vba.CreateStream(streamName);
        module.Write(compressed, 0, compressed.Length);
        module.Flush();
    }

    private static string BuildProjectText()
    {
        // Explizite CRLF-Zeilenenden (kein AppendLine): Der PROJECT-Stream muss
        // plattformunabhängig byte-identisch sein — VbaContentHasher splittet
        // MS-OVBA 2.4.2.6-strikt auf "\r\n"; AppendLine würde unter Linux "\n"
        // emitieren, die Projekt-Properties blieben ungehasht und der V3-Golden-
        // Value bräche (CI-Fehler: Digest-Drift Windows/Linux).
        var lines = new string[]
        {
            "ID=\"{11111111-2222-3333-4444-555555555555}\"",
            "Document=ThisWorkbook/&H00000000",
            "Module=CleanModule",
            "BaseClass=frmTest",
            "Package={AC9F2F90-E877-11CE-9F68-00AA00574A4F}",
            "HelpFile=\"\"",
            $"Name=\"{ProjectName}\"",
            "HelpContextID=\"0\"",
            "Description=\"OSSP signing fixture\"",
            "VersionCompatible32=\"393222000\"",
            "CMG=\"0604AA00EA009E049E049A089A08\"",
            "DPB=\"B6B41AD07A30374D374DC8B3384DDC63D35C51C89D809616E325E4129493EEFDBC48EE77D47B79\"",
            "GC=\"6664CAA0CAE07BE17BE17B\"",
            "[Host Extender Info]",
            "&H00000001={3832D640-CF90-11CF-8E43-00A0C911005A};VBE;&H00000000",
            "[Workspace]",
            "CleanModule=0, 0, 0, 0, C",
        };

        return string.Join("\r\n", lines) + "\r\n";
    }

    private static byte[] BuildDirStream()
    {
        using var stream = new MemoryStream();
        using var writer = new BinaryWriter(stream, Encoding.UTF8, leaveOpen: true);

        WriteSizedRecord(writer, 0x0001, u32(0x00000001));                 // PROJECTSYSKIND (Win32)
        WriteSizedRecord(writer, 0x0002, u32(Lcid));                       // PROJECTLCID
        WriteSizedRecord(writer, 0x0014, u32(Lcid));                       // PROJECTLCIDINVOKE
        WriteSizedRecord(writer, 0x0003, u16(1252));                       // PROJECTCODEPAGE
        WriteSizedRecord(writer, 0x0004, mbcs(ProjectName));               // PROJECTNAME
        WriteSizedRecord(writer, 0x0005, mbcs(""));                        // PROJECTDOCSTRING
        WriteSizedRecord(writer, 0x0040, utf16(""));                       // PROJECTDOCSTRINGUNICODE
        WriteSizedRecord(writer, 0x0006, mbcs(""));                        // PROJECTHELPFILEPATH (1)
        WriteSizedRecord(writer, 0x003D, mbcs(""));                        // PROJECTHELPFILEPATH (2)
        WriteSizedRecord(writer, 0x0007, u32(0));                          // PROJECTHELPCONTEXT
        WriteSizedRecord(writer, 0x0008, u32(0));                          // PROJECTLIBFLAGS
        writer.Write((ushort)0x0009);                                      // PROJECTVERSION (kein Size-Feld)
        writer.Write((uint)0x00000004);                                    // Reserved
        writer.Write((uint)0x00000001);                                    // VersionMajor
        writer.Write((ushort)0x0000);                                      // VersionMinor
        WriteSizedRecord(writer, 0x000C, mbcs(""));                        // PROJECTCONSTANTS
        WriteSizedRecord(writer, 0x003C, utf16(""));                       // PROJECTCONSTANTSUNICODE

        WriteReferenceRegistered(writer, "stdole", "*\\G{00020430-0000-0000-C000-000000000046}#2.0#0#C:\\Windows\\System32\\stdole2.tlb#OLE Automation");
        WriteReferenceControl(writer, "ControlLib", "*\\G{01234567-89AB-CDEF-0123-456789ABCDEF}#1.0#0#C:\\Windows\\System32\\controllib.ocx#Control Lib",
            libidExtended: "*\\G{01234567-89AB-CDEF-0123-456789ABCDEF}#1.0#0#C:\\Windows\\System32\\controllib.exd#Control Lib");
        WriteReferenceOriginalWithControl(writer, "OrigControl", "*\\O{01234567-89AB-CDEF-0123-456789ABCDEF}#1.0#0#C:\\Windows\\System32\\orig.ocx#Orig", "*\\G{01234567-89AB-CDEF-0123-456789ABCDEF}#1.0#0#C:\\Windows\\System32\\orig.ocx#Orig");

        writer.Write((ushort)0x000F);                                      // PROJECTMODULES
        writer.Write((uint)0x00000002);                                    // Size (ModuleCount folgt)
        writer.Write((ushort)0x0002);                                      // ModuleCount
        WriteSizedRecord(writer, 0x0013, u16(0xFFFF));                     // PROJECTCOOKIE

        WriteModuleRecords(writer, "CleanModule", procedural: true, readOnly: false, privateModule: false);
        WriteModuleRecords(writer, "ThisWorkbook", procedural: false, readOnly: false, privateModule: true);

        writer.Write((ushort)0x0010);                                      // PROJECTTERMINATOR
        writer.Write((uint)0x00000000);                                    // Reserved

        writer.Flush();
        return stream.ToArray();

        static byte[] mbcs(string value) => Encoding.GetEncoding(CodePage).GetBytes(value);
        static byte[] utf16(string value) => Encoding.Unicode.GetBytes(value);
        static byte[] u16(ushort value) => [(byte)(value & 0xFF), (byte)(value >> 8)];
        static byte[] u32(uint value) => [(byte)(value & 0xFF), (byte)((value >> 8) & 0xFF), (byte)((value >> 16) & 0xFF), (byte)(value >> 24)];
    }

    private static void WriteSizedRecord(BinaryWriter writer, ushort id, byte[] payload)
    {
        writer.Write(id);
        writer.Write((uint)payload.Length);
        writer.Write(payload);
    }

    private static void WriteRecord(BinaryWriter writer, ushort id, byte[] payload)
    {
        writer.Write(id);
        writer.Write(payload);
    }

    private static void WriteNameRecord(BinaryWriter writer, string name)
    {
        WriteSizedRecord(writer, 0x0016, Encoding.GetEncoding(CodePage).GetBytes(name));
        writer.Write((ushort)0x003E); // Reserved: Id des folgenden Unicode-Records
        var unicode = Encoding.Unicode.GetBytes(name);
        writer.Write((uint)unicode.Length);
        writer.Write(unicode);
    }

    private static void WriteReferenceRegistered(BinaryWriter writer, string name, string libid)
    {
        WriteNameRecord(writer, name);
        var libidBytes = Encoding.GetEncoding(CodePage).GetBytes(libid);
        // MS-OVBA 2.3.4.2.2.2: Size deckt SizeOfLibid + Libid + Reserved1 + Reserved2 ab —
        // beide Größenfelder schreiben, so wie es echtes Office tut (Golden-Files, AK-51).
        writer.Write((ushort)0x000D);                                      // REFERENCEREGISTERED
        writer.Write((uint)(sizeof(uint) + libidBytes.Length + sizeof(uint) + sizeof(ushort)));
        writer.Write((uint)libidBytes.Length);                             // SizeOfLibid
        writer.Write(libidBytes);
        writer.Write((uint)0x00000000);                                    // Reserved1
        writer.Write((ushort)0x0000);                                      // Reserved2
    }

    private static void WriteReferenceControl(BinaryWriter writer, string name, string libidTwiddled, string? libidExtended = null)
    {
        WriteNameRecord(writer, name);
        writer.Write((ushort)0x002F);                                      // REFERENCECONTROL
        var twiddled = Encoding.GetEncoding(CodePage).GetBytes(libidTwiddled);
        writer.Write((uint)twiddled.Length);
        writer.Write(twiddled);
        writer.Write((uint)0x00000000);                                    // Reserved1
        writer.Write((ushort)0x0000);                                      // Reserved2

        if (libidExtended is not null)
        {
            writer.Write((ushort)0x0030);                                  // Extended-Record (Reserved3)
            var extended = Encoding.GetEncoding(CodePage).GetBytes(libidExtended);
            writer.Write((uint)extended.Length);
            writer.Write(extended);
            writer.Write((uint)0x00000000);                                // Reserved4
            writer.Write((ushort)0x0000);                                  // Reserved5
            writer.Write(new byte[16]);                                    // OriginalTypeLib (GUID)
            writer.Write((uint)0x00000000);                                // Cookie
        }
    }

    private static void WriteReferenceOriginalWithControl(BinaryWriter writer, string name, string libidOriginal, string libidTwiddled)
    {
        WriteNameRecord(writer, name);
        var original = Encoding.GetEncoding(CodePage).GetBytes(libidOriginal);
        writer.Write((ushort)0x0033);                                      // REFERENCEORIGINAL
        writer.Write((uint)original.Length);
        writer.Write(original);
        WriteReferenceControlBody(writer, libidTwiddled);
    }

    private static void WriteReferenceControlBody(BinaryWriter writer, string libidTwiddled)
    {
        var twiddled = Encoding.GetEncoding(CodePage).GetBytes(libidTwiddled);
        writer.Write((ushort)0x002F);                                      // REFERENCECONTROL
        writer.Write((uint)twiddled.Length);
        writer.Write(twiddled);
        writer.Write((uint)0x00000000);                                    // Reserved1
        writer.Write((ushort)0x0000);                                      // Reserved2 (kein Extended-Block)
    }

    private static void WriteModuleRecords(
        BinaryWriter writer, string name, bool procedural, bool readOnly, bool privateModule)
    {
        WriteSizedRecord(writer, 0x0019, Encoding.GetEncoding(CodePage).GetBytes(name)); // MODULENAME
        var unicode = Encoding.Unicode.GetBytes(name);
        writer.Write((ushort)0x0047);                                      // MODULENAMEUNICODE
        writer.Write((uint)unicode.Length);
        writer.Write(unicode);
        var streamName = Encoding.GetEncoding(CodePage).GetBytes(name);
        writer.Write((ushort)0x001A);                                      // MODULESTREAMNAME
        writer.Write((uint)streamName.Length);
        writer.Write(streamName);
        // MS-OVBA 2.3.4.2.3.2.3: Reserved(2) = 0x0032, dann UTF-16-Streamname —
        // beides schreibt echtes Office (Golden-Files, AK-51).
        var streamNameUnicode = Encoding.Unicode.GetBytes(name);
        writer.Write((ushort)0x0032);                                      // Reserved
        writer.Write((uint)streamNameUnicode.Length);                      // SizeOfStreamNameUnicode
        writer.Write(streamNameUnicode);
        WriteSizedRecord(writer, 0x001C, mbcsEmpty());                     // MODULEDOCSTRING
        writer.Write((ushort)0x0048);                                      // MODULEDOCSTRINGUNICODE
        writer.Write((uint)0x00000000);                                    // Size 0
        WriteSizedRecord(writer, 0x001E, u32b(0));                         // MODULEHELPCONTEXT
        WriteSizedRecord(writer, 0x002C, u16b(0xFFFF));                    // MODULECOOKIE
        WriteSizedRecord(writer, 0x0031, u32b(0));                         // MODULEOFFSET
        writer.Write((ushort)(procedural ? 0x0021 : 0x0022));              // MODULETYPE
        writer.Write((uint)0x00000000);                                    // Reserved
        if (readOnly)
        {
            writer.Write((ushort)0x0025);                                  // MODULEREADONLY
            writer.Write((uint)0x00000000);                                // Reserved
        }
        if (privateModule)
        {
            writer.Write((ushort)0x0028);                                  // MODULEPRIVATE
            writer.Write((uint)0x00000000);                                // Reserved
        }
        writer.Write((ushort)0x002B);                                      // MODULETERMINATOR
        writer.Write((uint)0x00000000);                                    // Reserved (MS-OVBA 2.3.4.2.3.2)

        static byte[] mbcsEmpty() => [];
        static byte[] u32b(uint value) => [(byte)(value & 0xFF), (byte)((value >> 8) & 0xFF), (byte)((value >> 16) & 0xFF), (byte)(value >> 24)];
        static byte[] u16b(ushort value) => [(byte)(value & 0xFF), (byte)(value >> 8)];
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
