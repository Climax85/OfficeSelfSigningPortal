namespace OfficeSelfSigningPortal.SigningService.Signing;

/// <summary>Raw-Felder eines REFERENCENAME-Records (0x0016) — alle Felder werden gehasht.</summary>
public sealed record ReferenceNameRecord(
    uint SizeOfName,
    byte[] Name,
    ushort Reserved,
    uint SizeOfNameUnicode,
    byte[] NameUnicode);

/// <summary>
/// Ein REFERENCE-Eintrag des dir-Streams (MS-OVBA 2.3.4.2.2.1). <see cref="NameRecord"/> wird
/// vor dem eigentlichen Referenz-Record gehasht; <see cref="RecordId"/> bestimmt, welche
/// Felder des Folgerecords gehasht werden (MS-OVBA 2.4.2.5). Ein optionaler
/// REFERENCEORIGINAL (0x0033) kann derselben REFERENCE vorangestellt sein; das
/// folgende REFERENCECONTROL wird dann in denselben Eintrag übernommen.
/// </summary>
public sealed class ReferenceEntry
{
    /// <summary>RecordId des führenden Records: 0x002F | 0x0033 | 0x000D | 0x000E.</summary>
    public required ushort RecordId { get; init; }

    public required ReferenceNameRecord NameRecord { get; init; }

    /// <summary>
    /// REFERENCEREGISTERED (0x000D): Größenfeld des Records (deckt SizeOfLibid + Libid +
    /// Reserved1 + Reserved2 ab, MS-OVBA 2.3.4.2.2.2). Wird für den Hash nicht
    /// reproduziert, dient aber der Validierung beim Parsen.
    /// </summary>
    public uint RegisteredSize { get; set; }

    /// <summary>REFERENCEREGISTERED (0x000D): SizeOfLibid + Libid + Reserved1 + Reserved2.</summary>
    public uint RegisteredSizeOfLibid { get; set; }

    public byte[] RegisteredLibid { get; set; } = [];

    public uint RegisteredReserved1 { get; set; }

    public ushort RegisteredReserved2 { get; set; }

    /// <summary>REFERENCEORIGINAL (0x0033): SizeOfLibidOriginal + LibidOriginal.</summary>
    public uint OriginalSizeOfLibid { get; set; }

    public byte[] OriginalLibid { get; set; } = [];

    /// <summary>
    /// REFERENCEPROJECT (0x000E): Größenfeld des Records (deckt beide Libids + Major/Minor ab,
    /// MS-OVBA 2.3.4.2.2.4). Wird für den Hash nicht reproduziert, dient der Validierung.
    /// </summary>
    public uint ProjectSize { get; set; }

    /// <summary>REFERENCEPROJECT (0x000E): beide Libids + Major/Minor.</summary>
    public uint ProjectSizeOfLibidAbsolute { get; set; }

    public byte[] ProjectLibidAbsolute { get; set; } = [];

    public uint ProjectSizeOfLibidRelative { get; set; }

    public byte[] ProjectLibidRelative { get; set; } = [];

    public uint ProjectMajorVersion { get; set; }

    public ushort ProjectMinorVersion { get; set; }

    // REFERENCECONTROL (0x002F) — alle Felder sind hash-relevant (MS-OVBA 2.4.2.5).
    public uint ControlSizeOfLibidTwiddled { get; set; }

    public byte[] ControlLibidTwiddled { get; set; } = [];

    public uint ControlReserved1 { get; set; }

    public ushort ControlReserved2 { get; set; }

    /// <summary>Wiederholter REFERENCENAME (0x0016) vor dem Extended-Block, sofern Reserved2 == 0x003E.</summary>
    public ReferenceNameRecord? ControlNameRecordExtended { get; set; }

    /// <summary>true, wenn der Extended-Block (ab 0x0030/Reserved3) vorhanden ist.</summary>
    public bool ControlHasExtendedBlock { get; set; }

    public uint ControlSizeOfLibidExtended { get; set; }

    public byte[] ControlLibidExtended { get; set; } = [];

    public uint ControlReserved4 { get; set; }

    public ushort ControlReserved5 { get; set; }

    public byte[] ControlOriginalTypeLib { get; set; } = []; // 16 Bytes (GUID)

    public uint ControlCookie { get; set; }
}

/// <summary>Ein MODULE-Eintrag des dir-Streams (MS-OVBA 2.3.4.2.3.2).</summary>
public sealed record ModuleEntry
{
    /// <summary>MODULENAME (0x0019), MBCS-Rohbytes.</summary>
    public required byte[] Name { get; init; }

    /// <summary>MODULENAMEUNICODE (0x0047), UTF-16LE-Rohbytes (leer ⇒ nicht vorhanden).</summary>
    public byte[] NameUnicode { get; init; } = [];

    /// <summary>MODULESTREAMNAME (0x001A), MBCS — Name des Modul-Streams im VBA-Speicher.</summary>
    public required string StreamName { get; init; }

    /// <summary>MODULESTREAMNAME: Reserved(2) vor dem Unicode-Teil (per Spec 0x0032, „MUST be ignored").</summary>
    public ushort StreamNameReserved { get; init; }

    /// <summary>MODULESTREAMNAME: StreamNameUnicode, UTF-16LE-Rohbytes.</summary>
    public byte[] StreamNameUnicode { get; init; } = [];

    /// <summary>MODULETERMINATOR (0x002B): Reserved(4).</summary>
    public uint TerminatorReserved { get; init; }

    /// <summary>MODULEOFFSET (0x0031) — Position des CompressedContainer im Modul-Stream.</summary>
    public required uint TextOffset { get; init; }

    /// <summary>MODULETYPE: true ⇒ 0x0021 (prozedural), false ⇒ 0x0022 (Klassen-/Dokumentenmodul).</summary>
    public required bool IsProcedural { get; init; }

    public uint TypeRecordReserved { get; init; }

    public bool ReadOnly { get; init; }

    public uint ReadOnlyReserved { get; init; }

    public bool Private { get; init; }

    public uint PrivateReserved { get; init; }
}

/// <summary>Geparstes Projektmodell des dekomprimierten dir-Streams (Hash-relevante Felder, MS-OVBA 2.4.2.5).</summary>
public sealed class DirStreamData
{
    public required int CodePage { get; init; }

    public required uint SysKindSize { get; init; }

    public required uint Lcid { get; init; }

    public required uint LcidInvoke { get; init; }

    public required byte[] ProjectName { get; init; }

    public required uint DocStringSize { get; init; }

    public required uint DocStringUnicodeSize { get; init; }

    public required uint HelpFile1Size { get; init; }

    public required uint HelpFile2Size { get; init; }

    public required uint HelpContextSize { get; init; }

    public required uint LibFlags { get; init; }

    public required uint VersionReserved { get; init; }

    public required uint VersionMajor { get; init; }

    public required ushort VersionMinor { get; init; }

    public required byte[] Constants { get; init; }

    public required byte[] ConstantsUnicode { get; init; }

    public required IReadOnlyList<ReferenceEntry> References { get; init; }

    public required IReadOnlyList<ModuleEntry> Modules { get; init; }

    /// <summary>PROJECTTERMINATOR-Reserved (u4 nach 0x0010) — wird mit gehasht.</summary>
    public required uint TerminatorReserved { get; init; }
}
