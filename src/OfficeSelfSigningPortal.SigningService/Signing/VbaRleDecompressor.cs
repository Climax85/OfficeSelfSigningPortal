namespace OfficeSelfSigningPortal.SigningService.Signing;

/// <summary>
/// Dekompression komprimierter VBA-Container nach MS-OVBA 2.4.1
/// (CompressedContainer: 0x01-Signatur, dann Chunk-Folge mit 2-Byte-Headern).
/// Eigene Implementierung im Signing-Kontext: Der SigningService darf keinen
/// Projekt-Referenz auf den WorkerService (Scanning-Domäne) aufbauen; der
/// Algorithmus ist spec-fix und spiegelt den reviewten Produktions-Dekompressor
/// des WorkerService (VbaRle) — beide Seiten sind gegen Spec-Vektoren getestet.
/// </summary>
public static class VbaRleDecompressor
{
    public const byte ContainerSignature = 0x01;

    private const int RawChunkDecompressedSize = 4096;
    private const int ChunkHeaderSignature = 0x3000; // Bits 12–14: 0b011

    /// <summary>
    /// Dekomprimiert einen CompressedContainer. Wirft <see cref="InvalidDataException"/>
    /// bei Signatur- oder Chunk-Verletzungen (Anhang C: Normalisierung bricht ab).
    /// </summary>
    public static byte[] Decompress(ReadOnlySpan<byte> container)
    {
        if (container.IsEmpty || container[0] != ContainerSignature)
        {
            throw new InvalidDataException("Ungültige Container-Signatur — kein MS-OVBA-CompressedContainer.");
        }

        using var output = new MemoryStream();
        var position = 1;

        while (position < container.Length)
        {
            if (container.Length - position < 2)
            {
                throw new InvalidDataException("Abgeschnittener Chunk-Header.");
            }

            var header = (int)container[position] | ((int)container[position + 1] << 8);
            var chunkSize = (header & 0x0FFF) + 3;
            var signature = header & 0x7000;
            var isCompressed = (header & 0x8000) != 0;

            if (signature != ChunkHeaderSignature)
            {
                throw new InvalidDataException("Ungültige Chunk-Signatur (Bits 12–14 != 0b011).");
            }

            if (container.Length - position < chunkSize)
            {
                throw new InvalidDataException("Abgeschnittener Chunk.");
            }

            if (!isCompressed)
            {
                // Unkomprimierter Chunk: exakt 4096 Rohbytes (Ende ggf. abgeschnitten).
                var rawLength = Math.Min(RawChunkDecompressedSize, container.Length - position - 2);
                output.Write(container.Slice(position + 2, rawLength));
                position += chunkSize;
                continue;
            }

            DecompressChunk(container.Slice(position + 2, chunkSize - 2), output);
            position += chunkSize;
        }

        return output.ToArray();
    }

    private static void DecompressChunk(ReadOnlySpan<byte> chunk, MemoryStream output)
    {
        var chunkStart = output.Length;
        var position = 0;

        while (position < chunk.Length)
        {
            var flags = chunk[position];
            position++;

            for (var bit = 0; bit < 8 && position < chunk.Length; bit++)
            {
                if ((flags & (1 << bit)) == 0)
                {
                    output.WriteByte(chunk[position]);
                    position++;
                    continue;
                }

                if (chunk.Length - position < 2)
                {
                    throw new InvalidDataException("Abgeschnittener Copy-Token.");
                }

                var token = (int)chunk[position] | ((int)chunk[position + 1] << 8);
                position += 2;

                var (bitCount, lengthMask, offsetMask) = CopyTokenHelp(output.Length - chunkStart);
                var length = (token & lengthMask) + 3;
                var offset = ((token & offsetMask) >> (16 - bitCount)) + 1;

                var sourcePosition = output.Length - offset;
                if (sourcePosition < chunkStart || offset <= 0)
                {
                    throw new InvalidDataException("Copy-Token zeigt außerhalb des Chunks.");
                }

                // Byte-weises Kopieren, da Quell- und Zielbereich sich überlappen können.
                for (var i = 0; i < length; i++)
                {
                    output.WriteByte(output.GetBuffer()[(int)sourcePosition + i]);
                }
            }
        }
    }

    /// <summary>MS-OVBA 2.4.1.1.5: Bit-Aufteilung des 16-Bit-Copy-Tokens abhängig vom Fortschritt im Chunk.</summary>
    private static (int BitCount, int LengthMask, int OffsetMask) CopyTokenHelp(long decompressedChunkLength)
    {
        var difference = Math.Max(decompressedChunkLength, 1);
        var bitCount = 4;
        while ((1L << bitCount) < difference)
        {
            bitCount++;
        }

        var lengthMask = 0xFFFF >> bitCount;
        var offsetMask = (~lengthMask) & 0xFFFF;
        return (bitCount, lengthMask, offsetMask);
    }
}
