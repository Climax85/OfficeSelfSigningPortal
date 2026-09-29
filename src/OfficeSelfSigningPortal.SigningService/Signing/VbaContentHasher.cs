using System.Text;
using System.Text.RegularExpressions;
using OpenMcdf;

namespace OfficeSelfSigningPortal.SigningService.Signing;

/// <summary>
/// MS-OVBA-V3-Contents-Hash (§2.4.2.7): SHA-256 über
/// <c>ContentBuffer = V3ContentNormalizedData (§2.4.2.5) || ProjectNormalizedData (§2.4.2.6)</c>.
/// Die Implementierung folgt dem Spec-Pseudocode wörtlich; Referenz-Abgleich erfolgte
/// gegen EPPlus (<c>V3NormalizedDataHashInputProvider</c>, interop-erprobt mit Excel),
/// inkl. dessen Auslegung der PROJECT-Stream-Zeilen (Split auf CRLF) und der
/// Designer-Storage-Normalisierung (§2.4.2.2, 1023-Byte-Blöcke, zero-padded).
/// </summary>
public static class VbaContentHasher
{
    static VbaContentHasher()
    {
        // MBCS-Codepages (PROJECTCODEPAGE, typisch 1252) sind unter .NET nicht
        // eingebaut und müssen explizit nachregistriert werden.
        Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
    }

    private const byte Lf = 0x0A;

    private static readonly string[] DefaultAttributes =
    [
        "Attribute VB_Base = \"0{00020820-0000-0000-C000-000000000046}\"",
        "Attribute VB_GlobalNameSpace = False",
        "Attribute VB_Creatable = False",
        "Attribute VB_PredeclaredId = True",
        "Attribute VB_Exposed = True",
        "Attribute VB_TemplateDerived = False",
        "Attribute VB_Customizable = True",
    ];

    /// <summary>
    /// Berechnet den V3-Contents-Hash des VBA-Projekts (SHA-256).
    /// <paramref name="vbaProject"/> sind die Rohbytes des <c>vbaProject.bin</c>-Parts (MS-CFB).
    /// </summary>
    public static byte[] ComputeV3ContentHash(byte[] vbaProject)
    {
        ArgumentNullException.ThrowIfNull(vbaProject);

        using var compound = new CompoundFile(new MemoryStream(vbaProject, writable: false));
        var vbaStorage = compound.RootStorage.GetStorage("VBA");
        var dirStream = vbaStorage.GetStream("dir").GetData();
        var projectStream = compound.RootStorage.GetStream("PROJECT").GetData();

        var decompressedDir = VbaRleDecompressor.Decompress(dirStream);
        var dir = DirStreamReader.Parse(decompressedDir, fallbackCodePage: 1252);
        var codePage = Encoding.GetEncoding(dir.CodePage);

        using var buffer = new MemoryStream();
        var writer = new BinaryWriter(buffer, Encoding.UTF8, leaveOpen: true);

        WriteV3ContentNormalizedData(writer, dir, vbaStorage, codePage);
        WriteProjectNormalizedData(writer, projectStream, compound.RootStorage, codePage);

        writer.Flush();
        return System.Security.Cryptography.SHA256.HashData(buffer.ToArray());
    }

    /// <summary>MS-OVBA 2.4.2.5 — V3ContentNormalizedData aus dem dekomprimierten dir-Stream.</summary>
    private static void WriteV3ContentNormalizedData(
        BinaryWriter buffer, DirStreamData dir, CFStorage vbaStorage, Encoding codePage)
    {
        buffer.Write((ushort)0x0001); // PROJECTSYSKIND.Id
        buffer.Write(dir.SysKindSize); // PROJECTSYSKIND.Size

        buffer.Write((ushort)0x0002); // PROJECTLCID.Id
        buffer.Write((uint)0x00000004); // PROJECTLCID.Size
        buffer.Write(dir.Lcid); // PROJECTLCID.Lcid

        buffer.Write((ushort)0x0014); // PROJECTLCIDINVOKE.Id
        buffer.Write((uint)0x00000004); // PROJECTLCIDINVOKE.Size
        buffer.Write(dir.LcidInvoke); // PROJECTLCIDINVOKE.LcidInvoke

        buffer.Write((ushort)0x0003); // PROJECTCODEPAGE.Id
        buffer.Write((uint)0x00000002); // PROJECTCODEPAGE.Size

        buffer.Write((ushort)0x0004); // PROJECTNAME.Id
        buffer.Write((uint)dir.ProjectName.Length);
        buffer.Write(dir.ProjectName);

        buffer.Write((ushort)0x0005); // PROJECTDOCSTRING.Id
        buffer.Write(dir.DocStringSize); // PROJECTDOCSTRING.SizeOfDocString
        buffer.Write((ushort)0x0040); // PROJECTDOCSTRING.Reserved (Unicode-Record-Id)
        buffer.Write(dir.DocStringUnicodeSize); // PROJECTDOCSTRING.SizeOfDocStringUnicode

        buffer.Write((ushort)0x0006); // PROJECTHELPFILEPATH.Id
        buffer.Write(dir.HelpFile1Size); // PROJECTHELPFILEPATH.SizeOfHelpFile1
        buffer.Write((ushort)0x003D); // PROJECTHELPFILEPATH.Reserved
        buffer.Write(dir.HelpFile2Size); // PROJECTHELPFILEPATH.SizeOfHelpFile2

        buffer.Write((ushort)0x0007); // PROJECTHELPCONTEXT.Id
        buffer.Write(dir.HelpContextSize); // PROJECTHELPCONTEXT.Size

        buffer.Write((ushort)0x0008); // PROJECTLIBFLAGS.Id
        buffer.Write((uint)0x00000004); // PROJECTLIBFLAGS.Size
        buffer.Write(dir.LibFlags); // PROJECTLIBFLAGS.ProjectLibFlags

        buffer.Write((ushort)0x0009); // PROJECTVERSION.Id
        buffer.Write(dir.VersionReserved); // PROJECTVERSION.Reserved
        buffer.Write(dir.VersionMajor); // PROJECTVERSION.VersionMajor
        buffer.Write(dir.VersionMinor); // PROJECTVERSION.VersionMinor

        buffer.Write((ushort)0x000C); // PROJECTCONSTANTS.Id
        buffer.Write((uint)dir.Constants.Length);
        buffer.Write(dir.Constants);
        buffer.Write((ushort)0x003C); // PROJECTCONSTANTS.Reserved
        buffer.Write((uint)dir.ConstantsUnicode.Length);
        buffer.Write(dir.ConstantsUnicode);

        foreach (var reference in dir.References)
        {
            WriteReference(buffer, reference, codePage);
        }

        buffer.Write((ushort)0x000F); // PROJECTMODULES.Id
        buffer.Write((uint)0x00000002); // PROJECTMODULES.Size

        buffer.Write((ushort)0x0013); // PROJECTCOOKIE.Id
        buffer.Write((uint)0x00000002); // PROJECTCOOKIE.Size

        foreach (var module in dir.Modules)
        {
            WriteModule(buffer, module, vbaStorage, codePage);
        }

        buffer.Write((ushort)0x0010); // PROJECTTERMINATOR.Id
        buffer.Write(dir.TerminatorReserved); // PROJECTTERMINATOR.Reserved
    }

    private static void WriteReference(BinaryWriter buffer, ReferenceEntry reference, Encoding codePage)
    {
        buffer.Write((ushort)0x0016); // REFERENCENAME.Id
        buffer.Write(reference.NameRecord.SizeOfName);
        buffer.Write(reference.NameRecord.Name);
        buffer.Write(reference.NameRecord.Reserved);
        buffer.Write(reference.NameRecord.SizeOfNameUnicode);
        buffer.Write(reference.NameRecord.NameUnicode);

        switch (reference.RecordId)
        {
            case 0x002F:
                buffer.Write((ushort)0x002F);
                buffer.Write(reference.ControlSizeOfLibidTwiddled);
                buffer.Write(reference.ControlLibidTwiddled);
                buffer.Write(reference.ControlReserved1);
                buffer.Write(reference.ControlReserved2);

                if (reference.ControlNameRecordExtended is { } nameExtended)
                {
                    buffer.Write((ushort)0x0016);
                    buffer.Write(nameExtended.SizeOfName);
                    buffer.Write(nameExtended.Name);
                    buffer.Write(nameExtended.Reserved);
                    buffer.Write(nameExtended.SizeOfNameUnicode);
                    buffer.Write(nameExtended.NameUnicode);
                }

                if (reference.ControlHasExtendedBlock)
                {
                    buffer.Write((ushort)0x0030); // REFERENCECONTROL.Reserved3
                    buffer.Write(reference.ControlSizeOfLibidExtended);
                    buffer.Write(reference.ControlLibidExtended);
                    buffer.Write(reference.ControlReserved4);
                    buffer.Write(reference.ControlReserved5);
                    buffer.Write(reference.ControlOriginalTypeLib);
                    buffer.Write(reference.ControlCookie);
                }
                break;

            case 0x0033:
                buffer.Write((ushort)0x0033);
                buffer.Write(reference.OriginalSizeOfLibid);
                buffer.Write(reference.OriginalLibid);
                break;

            case 0x000D:
                buffer.Write((ushort)0x000D);
                buffer.Write(reference.RegisteredSizeOfLibid);
                buffer.Write(reference.RegisteredLibid);
                buffer.Write(reference.RegisteredReserved1);
                buffer.Write(reference.RegisteredReserved2);
                break;

            case 0x000E:
                buffer.Write((ushort)0x000E);
                buffer.Write(reference.ProjectSizeOfLibidAbsolute);
                buffer.Write(reference.ProjectLibidAbsolute);
                buffer.Write(reference.ProjectSizeOfLibidRelative);
                buffer.Write(reference.ProjectLibidRelative);
                buffer.Write(reference.ProjectMajorVersion);
                buffer.Write(reference.ProjectMinorVersion);
                break;

            default:
                throw new InvalidDataException(
                    $"Nicht unterstützter REFERENCE-Record 0x{reference.RecordId:X4} für den V3-Hash.");
        }
    }

    private static void WriteModule(
        BinaryWriter buffer, ModuleEntry module, CFStorage vbaStorage, Encoding codePage)
    {
        if (module.IsProcedural)
        {
            buffer.Write((ushort)0x0021); // MODULETYPE (prozedural)
            buffer.Write(module.TypeRecordReserved);
        }

        if (module.ReadOnly)
        {
            buffer.Write((ushort)0x0025); // MODULEREADONLY.Id
            buffer.Write(module.ReadOnlyReserved);
        }

        if (module.Private)
        {
            buffer.Write((ushort)0x0028); // MODULEPRIVATE.Id
            buffer.Write(module.PrivateReserved);
        }

        var streamData = vbaStorage.GetStream(module.StreamName).GetData();
        if (module.TextOffset > streamData.Length)
        {
            throw new InvalidDataException(
                $"MODULEOFFSET ({module.TextOffset}) hinter Modul-Stream-Ende ({streamData.Length}) — Modul '{module.StreamName}'.");
        }

        var compressed = new ReadOnlySpan<byte>(streamData, (int)module.TextOffset, streamData.Length - (int)module.TextOffset);
        var text = VbaRleDecompressor.Decompress(compressed);

        var hashModuleNameFlag = false;
        foreach (var line in SplitLines(text))
        {
            if (!StartsWithIgnoreCase(line, "attribute"u8))
            {
                hashModuleNameFlag = true;
                buffer.Write(line);
                buffer.Write(Lf);
            }
            else if (StartsWithIgnoreCase(line, "Attribute VB_Name = "u8))
            {
                continue;
            }
            else if (!IsDefaultAttribute(line, codePage))
            {
                hashModuleNameFlag = true;
                buffer.Write(line);
                buffer.Write(Lf);
            }
        }

        if (hashModuleNameFlag)
        {
            if (module.NameUnicode.Length > 0)
            {
                buffer.Write(module.NameUnicode); // MODULENAMEUNICODE (UTF-16LE-Rohbytes)
            }
            else
            {
                buffer.Write(module.Name); // MODULENAME (MBCS-Rohbytes)
            }

            buffer.Write(Lf);
        }
    }

    /// <summary>
    /// Zeilensplitting nach Spec: CR oder LF (sofern nicht Teil von CRLF) beendet eine
    /// Zeile; nach dem letzten Zeichen wird der Rest-Puffer als letzte Zeile angehängt.
    /// </summary>
    private static IEnumerable<byte[]> SplitLines(byte[] text)
    {
        var lines = new List<byte[]>();
        var start = 0;
        byte previous = 0;
        for (var i = 0; i < text.Length; i++)
        {
            var current = text[i];
            if (current == 0x0D || (current == 0x0A && previous != 0x0D))
            {
                lines.Add(text[start..i]);
                start = i + 1;
            }

            previous = current;
        }

        lines.Add(text[start..]);
        return lines;
    }

    private static bool StartsWithIgnoreCase(byte[] line, ReadOnlySpan<byte> prefix)
    {
        if (line.Length < prefix.Length)
        {
            return false;
        }

        for (var i = 0; i < prefix.Length; i++)
        {
            var a = line[i];
            var b = prefix[i];
            if (a >= (byte)'A' && a <= (byte)'Z')
            {
                a = (byte)(a + 32);
            }

            if (b >= (byte)'A' && b <= (byte)'Z')
            {
                b = (byte)(b + 32);
            }

            if (a != b)
            {
                return false;
            }
        }

        return true;
    }

    private static bool IsDefaultAttribute(byte[] line, Encoding codePage)
    {
        var lineText = codePage.GetString(line);
        foreach (var attribute in DefaultAttributes)
        {
            if (string.Equals(lineText, attribute, StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// MS-OVBA 2.4.2.6 — ProjectNormalizedData aus dem PROJECT-Stream (textuell):
    /// Header-Properties ohne ID/Document/CMG/DPB/GC (Werte unquotiert), davor
    /// je BaseClass-Property die Normalisierung der Designer-Storage (§2.4.2.2);
    /// [Host Extender Info] wird als Literal plus Zeilen ohne NWLN angehängt;
    /// [Workspace] und übrige Sektionen werden ignoriert.
    /// </summary>
    private static void WriteProjectNormalizedData(
        BinaryWriter buffer, byte[] projectStream, CFStorage rootStorage, Encoding codePage)
    {
        var projectText = codePage.GetString(projectStream);
        var lines = Regex.Split(projectText, "\r\n");

        var currentCategory = string.Empty;
        var hostExtenders = new List<string>();
        var sawHostExtenderSection = false;

        foreach (var rawLine in lines)
        {
            var line = rawLine;
            if (line.StartsWith('[') && line.EndsWith(']'))
            {
                currentCategory = line.Substring(1, line.Length - 2);
                if (string.Equals(currentCategory, "Host Extender Info", StringComparison.Ordinal))
                {
                    sawHostExtenderSection = true;
                }

                continue;
            }

            if (currentCategory.Length > 0)
            {
                if (string.Equals(currentCategory, "Host Extender Info", StringComparison.Ordinal)
                    && line.Length > 0)
                {
                    hostExtenders.Add(line);
                }

                continue;
            }

            if (line.Length == 0 || !line.Contains('='))
            {
                continue;
            }

            var separator = line.IndexOf('=');
            var propertyName = line.Substring(0, separator);
            var propertyValue = line.Substring(separator + 1);

            if (string.Equals(propertyName, "BaseClass", StringComparison.OrdinalIgnoreCase))
            {
                WriteDesignerStorage(buffer, propertyValue, rootStorage);
            }

            if (propertyName is "ID" or "Document" or "CMG" or "DPB" or "GC")
            {
                continue;
            }

            if (propertyValue.StartsWith('"') && propertyValue.EndsWith('"') && propertyValue.Length >= 2)
            {
                propertyValue = propertyValue.Substring(1, propertyValue.Length - 2);
            }

            buffer.Write(codePage.GetBytes(propertyName));
            buffer.Write(codePage.GetBytes(propertyValue));
        }

        if (sawHostExtenderSection && hostExtenders.Count > 0)
        {
            buffer.Write(codePage.GetBytes("Host Extender Info"));
            foreach (var hostExtender in hostExtenders)
            {
                buffer.Write(codePage.GetBytes(hostExtender));
            }
        }
    }

    /// <summary>
    /// MS-OVBA 2.4.2.2 — NormalizeDesignerStorage: Stream-Bytes in 1023-Byte-Blöcken
    /// (letzter Block zero-padded), verschachtelte Storages rekursiv, Element-Reihenfolge
    /// der CFB-Verzeichnisreihenfolge.
    /// </summary>
    private static void WriteDesignerStorage(BinaryWriter buffer, string storageName, CFStorage rootStorage)
    {
        if (!rootStorage.TryGetStorage(storageName, out var designerStorage))
        {
            throw new InvalidDataException(
                $"Designer-Storage '{storageName}' (BaseClass-Property) fehlt im VBA-Projekt.");
        }

        WriteStorageNormalized(buffer, designerStorage);
    }

    private static void WriteStorageNormalized(BinaryWriter buffer, CFStorage storage)
    {
        storage.VisitEntries(
            entry =>
            {
                if (entry.IsStream)
                {
                    var data = ((CFStream)entry).GetData();
                    var offset = 0;
                    while (offset < data.Length)
                    {
                        var chunkLength = Math.Min(1023, data.Length - offset);
                        buffer.Write(data, offset, chunkLength);
                        for (var i = chunkLength; i < 1023; i++)
                        {
                            buffer.Write((byte)0);
                        }

                        offset += chunkLength;
                    }
                }
                else if (entry.IsStorage)
                {
                    WriteStorageNormalized(buffer, (CFStorage)entry);
                }
            },
            recursive: false);
    }
}
