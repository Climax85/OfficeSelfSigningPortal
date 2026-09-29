using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace OfficeSelfSigningPortal.SigningService.Signing;

/// <summary>
/// Byte-Layout des VBA-V3-Signatur-Parts (MS-OSHARED §2.3.2): Die Strukturen werden von
/// Office über Offset-Felder (nicht streng-DER) gelesen; das Layout folgt daher 1:1 der
/// interop-erprobten EPPlus-Implementierung (CertUtil.GetSerializedCertStore /
/// CreateBinarySignature / ProjectSignUtil.CreateContentInfo).
/// </summary>
public static class VbaSignatureBlob
{
    // OID-Rohbytes (ohne Tag/Länge), MS-OSHARED §2.3.2.4.3.1 bzw. §2.3.2.4.3.2.
    private static readonly byte[] IndirectDataContentV3OidBytes = [0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x01, 0x1F];
    private static readonly byte[] Sha256OidBytes = [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
    private const string Sha256OidAscii = "2.16.840.1.101.3.4.2.1";

    /// <summary>
    /// SpcIndirectDataContent (eContent des SignedCms): data (SpcAttributeTypeAndOptionalValue
    /// mit SigFormatDescriptorV1) + DigestInfo, dessen digest-OCTET-STRING ein
    /// SigDataV1Serialized mit dem V3-Contents-Hash ist.
    /// </summary>
    public static byte[] CreateSpcIndirectDataContent(byte[] contentHash)
    {
        using var content = new MemoryStream();
        var writer = new BinaryWriter(content, Encoding.UTF8, leaveOpen: true);

        var hashContentBytes = CreateSigDataV1Serialized(contentHash);

        // EPPlus-Layout: Die eingebetteten Längen (0x0E/0x20/oidLen+7) sind nicht streng
        // DER-korrekt, werden von Office aber über die Offset-Felder gelesen — 1:1-Übernahme.
        writer.Write((byte)0x30); // SEQUENCE (SpcIndirectDataContent)
        WriteSequenceLength(writer, Sha256OidBytes.Length + hashContentBytes.Length + 0x24);
        writer.Write((byte)0x30); // SEQUENCE (SpcAttributeTypeAndOptionalValue)
        writer.Write((byte)0x0E);
        WriteOid(writer, IndirectDataContentV3OidBytes);
        writer.Write((byte)0x04); // OCTET STRING (SigFormatDescriptorV1)
        writer.Write((byte)0x0C);
        writer.Write(12); // Größe des Deskriptor-Records
        writer.Write(1); // Version
        writer.Write(1); // Format
        writer.Write((byte)0x30); // SEQUENCE (DigestInfo)
        writer.Write((byte)0x20);
        writer.Write((byte)0x30); // SEQUENCE (AlgorithmIdentifier)
        writer.Write((byte)(Sha256OidBytes.Length + 7));
        WriteOid(writer, Sha256OidBytes);
        writer.Write((byte)0x05); // NULL
        writer.Write((byte)0x00);
        writer.Write(hashContentBytes);

        writer.Flush();
        return content.ToArray();
    }

    /// <summary>SigDataV1Serialized als OCTET-STRING-TLV (DigestInfo.digest).</summary>
    private static byte[] CreateSigDataV1Serialized(byte[] contentHash)
    {
        using var data = new MemoryStream();
        var writer = new BinaryWriter(data, Encoding.UTF8, leaveOpen: true);

        const int headerSize = 4 * 6; // sechs u32-Offset-/Größenfelder
        var descriptorLength = headerSize + Sha256OidAscii.Length + 1 + contentHash.Length;

        writer.Write((byte)0x04); // OCTET STRING
        writer.Write((byte)descriptorLength);
        writer.Write(Sha256OidAscii.Length + 1); // AlgorithmId-Länge inkl. Terminator
        writer.Write(0); // compiled hash size (leer)
        writer.Write(contentHash.Length); // source hash size
        writer.Write(headerSize); // algorithm id offset
        writer.Write(headerSize + Sha256OidAscii.Length + 1); // compiled hash offset (leer)
        writer.Write(headerSize + Sha256OidAscii.Length + 1); // source hash offset
        writer.Write(Encoding.ASCII.GetBytes(Sha256OidAscii));
        writer.Write((byte)0); // String-Terminator
        writer.Write(contentHash);

        writer.Flush();
        return data.ToArray();
    }

    /// <summary>VBASigSerializedCertStore (MS-OSHARED §2.3.2.5.5) mit dem Signierzertifikat.</summary>
    public static byte[] CreateSerializedCertStore(byte[] certificateRawData)
    {
        using var store = new MemoryStream();
        var writer = new BinaryWriter(store, Encoding.UTF8, leaveOpen: true);

        writer.Write((uint)0); // Version
        writer.Write((uint)0x54524543); // fileType "CERT"
        writer.Write((uint)0x20); // SerializedCertificateEntry: CertId
        writer.Write((uint)1); // SerializedCertificateEntry: Verbleibende Anzahl
        writer.Write((uint)certificateRawData.Length); // cbCert
        writer.Write(certificateRawData);
        writer.Write((uint)0); // EndElementMarkerEntry
        writer.Write((ulong)0);

        writer.Flush();
        return store.ToArray();
    }

    /// <summary>
    /// DigSigInfoSerialized (MS-OSHARED §2.3.2.1): Offset-Header, CMS-DER, CertStore,
    /// leere Projektname-/Timestamp-Puffer. Das ist der Inhalt von vbaProjectSignatureV3.bin.
    /// </summary>
    public static byte[] CreateDigSigInfoSerialized(X509Certificate2 certificate, byte[] signedCmsDer)
    {
        var certStore = CreateSerializedCertStore(certificate.RawData);

        using var blob = new MemoryStream();
        var writer = new BinaryWriter(blob, Encoding.UTF8, leaveOpen: true);

        const uint headerSize = 44; // Offset-Basis hinter dem 36-Byte-Header (EPPlus-Konstante)
        writer.Write((uint)signedCmsDer.Length); // cbSignature
        writer.Write(headerSize); // certStoreOffset-Basis
        writer.Write((uint)certStore.Length); // cbSigningCertStore
        writer.Write((uint)(signedCmsDer.Length + headerSize)); // certStoreOffset
        writer.Write((uint)0); // cbProjectName
        writer.Write((uint)(signedCmsDer.Length + certStore.Length + headerSize)); // projectNameOffset
        writer.Write((uint)0); // fTimestamp
        writer.Write((uint)0); // cbTimestampUrl
        writer.Write((uint)(signedCmsDer.Length + certStore.Length + headerSize + 2)); // timestampUrlOffset
        writer.Write(signedCmsDer);
        writer.Write(certStore);
        writer.Write((ushort)0); // rgchProjectNameBuffer
        writer.Write((ushort)0); // rgchTimestampBuffer
        writer.Write((ushort)0);

        writer.Flush();
        return blob.ToArray();
    }

    private static void WriteOid(BinaryWriter writer, byte[] oidBytes)
    {
        writer.Write((byte)0x06); // OID-Tag
        writer.Write((byte)oidBytes.Length);
        writer.Write(oidBytes);
    }

    /// <summary>EPPlus WriteSequenceLength: kurze Form bzw. Längen-Überlauf-Korrektur.</summary>
    private static void WriteSequenceLength(BinaryWriter writer, int length)
    {
        if (length < 0x80)
        {
            writer.Write((byte)length);
            return;
        }

        var bytes = GetByteSize(length);
        length += bytes;
        var corrected = GetByteSize(length);
        if (bytes != corrected)
        {
            length++;
            bytes = corrected;
        }

        writer.Write((byte)(0x80 | bytes));
        var lengthBytes = BitConverter.GetBytes(length);
        for (var i = 0; i < bytes; i++)
        {
            writer.Write(lengthBytes[bytes - i - 1]);
        }
    }

    private static int GetByteSize(int length)
        => length < 0xFF ? 1 : length < 0xFFFF ? 2 : length < 0xFFFFFF ? 3 : 4;
}
