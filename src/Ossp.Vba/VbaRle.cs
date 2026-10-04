namespace Ossp.Vba;

/// <summary>
/// Gemeinsamer MS-OVBA-2.4.1-Helfer (F6/S1): einzige RLE-Dekompressions-Implementierung
/// für komprimierte VBA-Container, geteilt zwischen WorkerService (Scan-Pfad:
/// <c>VbaProjectExtractor</c>) und SigningService (Signing-Pfad: <c>VbaContentHasher</c>).
/// Deterministisch unit-getestet inkl. eines handkonstruierten Copy-Token-Vektors und
/// Korrupt-Fällen.
/// </summary>
public static class VbaRle
{
    public const byte ContainerSignature = 0x01;

    /// <summary>
    /// MS-CFB-Magic-Bytes (F6/S2): zentrale Quelle der OLE2-Compound-File-Signatur
    /// <c>D0 CF 11 E0 A1 B1 1A E1</c>. Geteilt zwischen WebUI (Polyglot-Erkennung) und
    /// WorkerService (OOXML-/CFB-VBA-Extraktion).
    /// </summary>
    public static byte[] CfbMagic => [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];

    private const int RawChunkDecompressedSize = 4096;
    private const int ChunkHeaderSignature = 0x3000; // Bits 12–14: 0b011

    /// <summary>
    /// Dekomprimiert einen CompressedContainer. Wirft <see cref="InvalidDataException"/>
    /// bei Signatur- oder Chunk-Verletzungen — der Aufrufer mappt das je nach Pfad auf
    /// EncryptedProject/ParserError (AK-45) oder bricht die Normalisierung ab (Anhang C).
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