using OfficeSelfSigningPortal.WorkerService.Scanning.Vba;

namespace OfficeSelfSigningPortal.TestSupport;

/// <summary>
/// Store-only-Kompressor für MS-OVBA-CompressedContainer (Testkorpus): Daten-Chunks
/// werden unkomprimiert abgelegt (CompressedChunkFlag = 0); die leere Payload als
/// komprimierter Leer-Chunk (ein Flag-Byte 0x00). Ausreichend für synthetische
/// Corpus-Dateien — der Produktions-Dekompressor beherrscht beide Chunk-Typen.
/// </summary>
public static class VbaRleCompressor
{
    public const int RawChunkSize = 4096;

    /// <summary>Komprimiert zu [0x01 | Chunks].</summary>
    public static byte[] CompressStoreOnly(byte[] data)
    {
        using var output = new MemoryStream();
        output.WriteByte(VbaRle.ContainerSignature);

        if (data.Length == 0)
        {
            // Komprimierter Leer-Chunk: Header (Size=3→Feld 0, Flag=1) + Flag-Byte ohne Tokens.
            output.WriteByte(0x00);
            output.WriteByte(0xB0);
            output.WriteByte(0x00);
            return output.ToArray();
        }

        for (var offset = 0; offset < data.Length; offset += RawChunkSize)
        {
            var length = Math.Min(RawChunkSize, data.Length - offset);
            var chunkSize = 2 + length;
            var header = 0x3000 | (chunkSize - 3);
            output.WriteByte((byte)(header & 0xFF));
            output.WriteByte((byte)((header >> 8) & 0xFF));
            output.Write(data, offset, length);
        }

        return output.ToArray();
    }
}
