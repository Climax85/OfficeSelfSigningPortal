using System.Text;

namespace OfficeSelfSigningPortal.SigningService.Signing;

/// <summary>
/// Cursor-Parser für den dekomprimierte dir-Stream eines VBA-Projekts
/// (MS-OVBA 2.3.4.2). Die Record-Layouts sind heterogen (nicht alle Records tragen
/// ein Size-Feld — MODULETYPE 0x0021/0x0022 hat z. B. nur Id + Reserved u4);
/// der Parser folgt daher einem expliziten Record-Switch. Vorbild für IDs und
/// Konsumationslogik ist der reviewte EPPlus-DirStream-Reader, abgeglichen mit
/// MS-OVBA 2.3.4.2. Alle hash-relevanten Felder (MS-OVBA 2.4.2.5) werden im Modell
/// festgehalten, inkl. Reserved-Werten und des vollständigen REFERENCECONTROL-Blocks.
/// </summary>
public static class DirStreamReader
{
    public static DirStreamData Parse(byte[] decompressedDir, int fallbackCodePage)
    {
        ArgumentNullException.ThrowIfNull(decompressedDir);

        var reader = new Cursor(decompressedDir);

        uint sysKindSize = 0, lcid = 0, lcidInvoke = 0, libFlags = 0;
        uint versionReserved = 0, versionMajor = 0, helpContextSize = 0;
        ushort versionMinor = 0;
        var codePage = fallbackCodePage;
        byte[] projectName = [];
        uint docStringSize = 0, docStringUnicodeSize = 0;
        uint helpFile1Size = 0, helpFile2Size = 0;
        byte[] constants = [], constantsUnicode = [];
        var references = new List<ReferenceEntry>();
        var modules = new List<ModuleBuilder>();
        uint terminatorReserved = 0;

        ReferenceNameRecord? currentName = null;
        ModuleBuilder? currentModule = null;

        while (reader.Remaining > 0)
        {
            var id = reader.ReadUInt16();
            uint size;
            switch (id)
            {
                case 0x0001: // PROJECTSYSKIND
                    size = reader.ReadUInt32();
                    sysKindSize = size;
                    reader.Skip(size);
                    break;
                case 0x0002: // PROJECTLCID
                    size = reader.ReadUInt32();
                    lcid = reader.ReadUInt32();
                    break;
                case 0x0014: // PROJECTLCIDINVOKE
                    size = reader.ReadUInt32();
                    lcidInvoke = reader.ReadUInt32();
                    break;
                case 0x0003: // PROJECTCODEPAGE
                    size = reader.ReadUInt32();
                    codePage = reader.ReadUInt16();
                    break;
                case 0x0004: // PROJECTNAME
                    size = reader.ReadUInt32();
                    projectName = reader.ReadBytes(size);
                    break;
                case 0x0005: // PROJECTDOCSTRING (+ folgender 0x0040-Unicode-Record)
                    docStringSize = reader.ReadUInt32();
                    reader.Skip(docStringSize);
                    var docStringUnicodeId = reader.ReadUInt16();
                    if (docStringUnicodeId != 0x0040)
                    {
                        throw new InvalidDataException("PROJECTDOCSTRING ohne folgenden 0x0040-Unicode-Record.");
                    }
                    docStringUnicodeSize = reader.ReadUInt32();
                    reader.Skip(docStringUnicodeSize);
                    break;
                case 0x0006: // PROJECTHELPFILEPATH (+ folgender 0x003D-Record)
                    helpFile1Size = reader.ReadUInt32();
                    reader.Skip(helpFile1Size);
                    var helpFile2Id = reader.ReadUInt16();
                    if (helpFile2Id != 0x003D)
                    {
                        throw new InvalidDataException("PROJECTHELPFILEPATH ohne folgenden 0x003D-Record.");
                    }
                    helpFile2Size = reader.ReadUInt32();
                    reader.Skip(helpFile2Size);
                    break;
                case 0x0007: // PROJECTHELPCONTEXT
                    helpContextSize = reader.ReadUInt32();
                    reader.Skip(helpContextSize);
                    break;
                case 0x0008: // PROJECTLIBFLAGS
                    size = reader.ReadUInt32();
                    libFlags = reader.ReadUInt32();
                    break;
                case 0x0009: // PROJECTVERSION (kein Size-Feld: Id, Reserved, Major, Minor)
                    versionReserved = reader.ReadUInt32();
                    versionMajor = reader.ReadUInt32();
                    versionMinor = reader.ReadUInt16();
                    break;
                case 0x000C: // PROJECTCONSTANTS (+ folgender 0x003C-Unicode-Record)
                    size = reader.ReadUInt32();
                    constants = reader.ReadBytes(size);
                    var constantsUnicodeId = reader.ReadUInt16();
                    if (constantsUnicodeId != 0x003C)
                    {
                        throw new InvalidDataException("PROJECTCONSTANTS ohne folgenden 0x003C-Unicode-Record.");
                    }
                    var constantsUnicodeSize = reader.ReadUInt32();
                    constantsUnicode = reader.ReadBytes(constantsUnicodeSize);
                    break;
                case 0x0016: // REFERENCENAME
                    currentName = ReadNameRecord(reader);
                    break;
                case 0x000D: // REFERENCEREGISTERED
                {
                    var sizeOfLibid = reader.ReadUInt32();
                    var libid = reader.ReadBytes(sizeOfLibid);
                    var reserved1 = reader.ReadUInt32();
                    var reserved2 = reader.ReadUInt16();
                    references.Add(new ReferenceEntry { RecordId = id, NameRecord = currentName ?? throw MissingName(id),
                        RegisteredSizeOfLibid = sizeOfLibid,
                        RegisteredLibid = libid,
                        RegisteredReserved1 = reserved1,
                        RegisteredReserved2 = reserved2,
                    });
                    break;
                }
                case 0x000E: // REFERENCEPROJECT
                {
                    var sizeAbs = reader.ReadUInt32();
                    var libidAbs = reader.ReadBytes(sizeAbs);
                    var sizeRel = reader.ReadUInt32();
                    var libidRel = reader.ReadBytes(sizeRel);
                    var major = reader.ReadUInt32();
                    var minor = reader.ReadUInt16();
                    references.Add(new ReferenceEntry { RecordId = id, NameRecord = currentName ?? throw MissingName(id),
                        ProjectSizeOfLibidAbsolute = sizeAbs,
                        ProjectLibidAbsolute = libidAbs,
                        ProjectSizeOfLibidRelative = sizeRel,
                        ProjectLibidRelative = libidRel,
                        ProjectMajorVersion = major,
                        ProjectMinorVersion = minor,
                    });
                    break;
                }
                case 0x0033: // REFERENCEORIGINAL (optionaler Vorbau zu REFERENCECONTROL)
                {
                    size = reader.ReadUInt32();
                    var libid = reader.ReadBytes(size);
                    references.Add(new ReferenceEntry { RecordId = id, NameRecord = currentName ?? throw MissingName(id),
                        OriginalSizeOfLibid = size,
                        OriginalLibid = libid,
                    });
                    break;
                }
                case 0x002F: // REFERENCECONTROL — komplette Feld-Erfassung (MS-OVBA 2.3.4.2.2.3)
                {
                    ReferenceEntry target;
                    if (references.Count > 0
                        && references[^1].RecordId == 0x0033
                        && references[^1].ControlSizeOfLibidTwiddled == 0)
                    {
                        // Folgerecord eines REFERENCEORIGINAL — dieselbe REFERENCE (der
                        // REFERENCENAME wird dadurch nur einmal gehasht, MS-OVBA 2.3.4.2.2.1).
                        target = references[^1];
                    }
                    else
                    {
                        target = new ReferenceEntry { RecordId = id, NameRecord = currentName ?? throw MissingName(id) };
                        references.Add(target);
                    }

                    ReadReferenceControl(reader, target);
                    break;
                }
                case 0x0019: // MODULENAME
                    size = reader.ReadUInt32();
                    currentModule = new ModuleBuilder { Name = reader.ReadBytes(size) };
                    modules.Add(currentModule);
                    break;
                case 0x0047: // MODULENAMEUNICODE
                    size = reader.ReadUInt32();
                    RequireModule(reader, currentModule, id).NameUnicode = reader.ReadBytes(size);
                    break;
                case 0x001A: // MODULESTREAMNAME (+ Reserved u4)
                    size = reader.ReadUInt32();
                    var streamNameBytes = reader.ReadBytes(size);
                    reader.ReadUInt32(); // Reserved
                    RequireModule(reader, currentModule, id).StreamName = Encoding.GetEncoding(codePage).GetString(streamNameBytes);
                    break;
                case 0x001C: // MODULEDOCSTRING (+ folgender Unicode-Record)
                    size = reader.ReadUInt32();
                    reader.Skip(size);
                    var moduleDocUnicodeId = reader.ReadUInt16();
                    var moduleDocUnicodeSize = reader.ReadUInt32();
                    reader.Skip(moduleDocUnicodeSize);
                    _ = moduleDocUnicodeId; // Layout-Validierung: Id wird nicht gehasht
                    break;
                case 0x001E: // MODULEHELPCONTEXT
                    size = reader.ReadUInt32();
                    reader.Skip(size);
                    break;
                case 0x002C: // MODULECOOKIE
                    size = reader.ReadUInt32();
                    reader.Skip(size);
                    break;
                case 0x0031: // MODULEOFFSET
                    size = reader.ReadUInt32();
                    RequireModule(reader, currentModule, id).TextOffset = reader.ReadUInt32();
                    _ = size; // per Spec stets 4
                    break;
                case 0x0025: // MODULEREADONLY (Id + Reserved u4)
                    RequireModule(reader, currentModule, id).ReadOnlyReserved = reader.ReadUInt32();
                    RequireModule(reader, currentModule, id).ReadOnly = true;
                    break;
                case 0x0028: // MODULEPRIVATE (Id + Reserved u4)
                    RequireModule(reader, currentModule, id).PrivateReserved = reader.ReadUInt32();
                    RequireModule(reader, currentModule, id).Private = true;
                    break;
                case 0x0021: // MODULETYPE prozedural (Id + Reserved u4)
                case 0x0022: // MODULETYPE Klasse/Dokument (Id + Reserved u4)
                {
                    var reserved = reader.ReadUInt32();
                    var module = RequireModule(reader, currentModule, id);
                    module.IsProcedural = id == 0x0021;
                    module.TypeRecordReserved = reserved;
                    break;
                }
                case 0x002B: // MODULETERMINATOR (Id only)
                    currentModule = null;
                    break;
                case 0x004A: // PROJECTCOMPATVERSION
                    size = reader.ReadUInt32();
                    reader.Skip(size);
                    break;
                case 0x000F: // PROJECTMODULES: Size u4, ModuleCount u2
                    size = reader.ReadUInt32();
                    reader.Skip(size);
                    break;
                case 0x0013: // PROJECTCOOKIE
                    size = reader.ReadUInt32();
                    reader.Skip(size);
                    break;
                case 0x0010: // PROJECTTERMINATOR — danach folgt Reserved u4
                    terminatorReserved = reader.Remaining >= 4 ? reader.ReadUInt32() : 0;
                    break;
                default:
                    throw new InvalidDataException($"Unbekannter dir-Stream-Record 0x{id:X4} an Position {reader.Position} (Laenge {decompressedDir.Length}) — Parsing abgebrochen.");
            }
        }

        return new DirStreamData
        {
            CodePage = codePage,
            SysKindSize = sysKindSize,
            Lcid = lcid,
            LcidInvoke = lcidInvoke,
            ProjectName = projectName,
            DocStringSize = docStringSize,
            DocStringUnicodeSize = docStringUnicodeSize,
            HelpFile1Size = helpFile1Size,
            HelpFile2Size = helpFile2Size,
            HelpContextSize = helpContextSize,
            LibFlags = libFlags,
            VersionReserved = versionReserved,
            VersionMajor = versionMajor,
            VersionMinor = versionMinor,
            Constants = constants,
            ConstantsUnicode = constantsUnicode,
            References = references,
            Modules = modules.Select(m => m.ToEntry()).ToList(),
            TerminatorReserved = terminatorReserved,
        };

        static InvalidDataException MissingName(ushort recordId) =>
            new($"REFERENCE-Record 0x{recordId:X4} ohne vorangehenden REFERENCENAME-Record.");
    }

    private static ReferenceNameRecord ReadNameRecord(Cursor reader)
    {
        var sizeOfName = reader.ReadUInt32();
        var name = reader.ReadBytes(sizeOfName);
        var reserved = reader.ReadUInt16();
        var sizeOfNameUnicode = reader.ReadUInt32();
        var nameUnicode = reader.ReadBytes(sizeOfNameUnicode);
        return new ReferenceNameRecord(sizeOfName, name, reserved, sizeOfNameUnicode, nameUnicode);
    }

    /// <summary>
    /// Liest einen REFERENCECONTROL-Record (0x002F) vollständig ein (MS-OVBA 2.3.4.2.2.3):
    /// Twiddled-Libid, Reserved1/2, optionaler wiederholter REFERENCENAME (Reserved2 ==
    /// 0x003E) und optionaler Extended-Block ab 0x0030 (Reserved3) mit LibidExtended,
    /// Reserved4/5, OriginalTypeLib (GUID) und Cookie.
    /// </summary>
    private static void ReadReferenceControl(Cursor reader, ReferenceEntry target)
    {
        var sizeTwiddled = reader.ReadUInt32();
        target.ControlSizeOfLibidTwiddled = sizeTwiddled;
        target.ControlLibidTwiddled = reader.ReadBytes(sizeTwiddled);
        target.ControlReserved1 = reader.ReadUInt32();
        target.ControlReserved2 = reader.ReadUInt16();

        if (target.ControlReserved2 == 0x003E)
        {
            var nameId = reader.ReadUInt16();
            if (nameId != 0x0016)
            {
                throw new InvalidDataException("REFERENCECONTROL: erwarteter wiederholter REFERENCENAME fehlt.");
            }
            target.ControlNameRecordExtended = ReadNameRecord(reader);
        }

        if (reader.Remaining >= 2 && reader.PeekUInt16() == 0x0030)
        {
            reader.ReadUInt16(); // Reserved3 (0x0030)
            target.ControlHasExtendedBlock = true;
            var sizeExtended = reader.ReadUInt32();
            target.ControlSizeOfLibidExtended = sizeExtended;
            target.ControlLibidExtended = reader.ReadBytes(sizeExtended);
            target.ControlReserved4 = reader.ReadUInt32();
            target.ControlReserved5 = reader.ReadUInt16();
            target.ControlOriginalTypeLib = reader.ReadBytes(16);
            target.ControlCookie = reader.ReadUInt32();
        }
    }

    private static ModuleBuilder RequireModule(Cursor reader, ModuleBuilder? module, ushort recordId)
    {
        if (module is null)
        {
            throw new InvalidDataException($"MODULE-Record 0x{recordId:X4} außerhalb eines MODULE-Kontexts (Offset {reader.Position}).");
        }
        return module;
    }

    private sealed class ModuleBuilder
    {
        public required byte[] Name { get; set; }
        public byte[] NameUnicode { get; set; } = [];
        public string? StreamName { get; set; }
        public uint? TextOffset { get; set; }
        public bool IsProcedural { get; set; }
        public uint TypeRecordReserved { get; set; }
        public bool ReadOnly { get; set; }
        public uint ReadOnlyReserved { get; set; }
        public bool Private { get; set; }
        public uint PrivateReserved { get; set; }

        public ModuleEntry ToEntry() => new()
        {
            Name = Name,
            NameUnicode = NameUnicode,
            StreamName = StreamName ?? throw new InvalidDataException("MODULE ohne MODULESTREAMNAME-Record."),
            TextOffset = TextOffset ?? throw new InvalidDataException("MODULE ohne MODULEOFFSET-Record."),
            IsProcedural = IsProcedural,
            TypeRecordReserved = TypeRecordReserved,
            ReadOnly = ReadOnly,
            ReadOnlyReserved = ReadOnlyReserved,
            Private = Private,
            PrivateReserved = PrivateReserved,
        };
    }

    /// <summary>Little-Endian-Cursor über den dekomprimierten dir-Stream.</summary>
    private sealed class Cursor
    {
        private readonly byte[] _data;
        private int _position;

        public Cursor(byte[] data) => _data = data;

        public int Position => _position;

        public int Remaining => _data.Length - _position;

        public ushort PeekUInt16() => (ushort)(_data[_position] | (_data[_position + 1] << 8));

        public ushort ReadUInt16()
        {
            Ensure(2);
            var value = PeekUInt16();
            _position += 2;
            return value;
        }

        public uint ReadUInt32()
        {
            Ensure(4);
            var value = (uint)(_data[_position]
                | (_data[_position + 1] << 8)
                | (_data[_position + 2] << 16)
                | (_data[_position + 3] << 24));
            _position += 4;
            return value;
        }

        public byte[] ReadBytes(uint count)
        {
            if (count > int.MaxValue)
            {
                throw new InvalidDataException("Record-Feld über int.MaxValue — korrupte Größenangabe.");
            }
            Ensure((int)count);
            var value = _data.AsSpan(_position, (int)count).ToArray();
            _position += (int)count;
            return value;
        }

        public void Skip(uint count)
        {
            if (count > int.MaxValue)
            {
                throw new InvalidDataException("Record-Feld über int.MaxValue — korrupte Größenangabe.");
            }
            Ensure((int)count);
            _position += (int)count;
        }

        private void Ensure(int count)
        {
            if (_data.Length - _position < count)
            {
                throw new InvalidDataException("Abgeschnittener dir-Stream-Record.");
            }
        }
    }
}
