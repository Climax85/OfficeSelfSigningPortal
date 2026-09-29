using OfficeSelfSigningPortal.TestSupport;
using OfficeSelfSigningPortal.WorkerService.Scanning.Vba;

namespace OfficeSelfSigningPortal.Tests.Scanning;

/// <summary>
/// MS-OVBA-2.4.1-Dekompression: Store-only-Roundtrip (Corpus-Erzeugung),
/// handkonstruierter Copy-Token-Vektor (komprimierter Pfad) und Korrupt-Fälle.
/// </summary>
public sealed class VbaRleTests
{
    [Fact]
    public void Decompress_StoreOnlyRoundtrip_liefertUrsprungsdaten()
    {
        // Arrange
        var original = new byte[9000]; // > ein Raw-Chunk → mehrere Chunks
        for (var i = 0; i < original.Length; i++)
        {
            original[i] = (byte)(i % 251);
        }

        var compressed = VbaRleCompressor.CompressStoreOnly(original);

        // Act
        var decompressed = VbaRle.Decompress(compressed);

        // Assert
        Assert.Equal(original, decompressed);
    }

    [Fact]
    public void Decompress_StoreOnlyLeerePayload_liefertLeeresArray()
    {
        // Arrange
        var compressed = VbaRleCompressor.CompressStoreOnly(Array.Empty<byte>());

        // Act
        var decompressed = VbaRle.Decompress(compressed);

        // Assert
        Assert.Empty(decompressed);
    }

    [Fact]
    public void Decompress_HandkonstruierterCopyToken_liefertErwarteteSequenz()
    {
        // Arrange: Container [0x01 | Chunk(Header 0xB003, Daten: Flag 0x02, Literal 'A', Token 0x0002)].
        // Token 0x0002 bei Decompress-Position 1 → bitCount 4, length (0x0002 & 0x0FFF) + 3 = 5,
        // offset ((0x0002 & 0xF000) >> 12) + 1 = 1 → "A" + 5× Kopie von Position -1 = "AAAAAA".
        byte[] container = [0x01, 0x03, 0xB0, 0x02, 0x41, 0x02, 0x00];

        // Act
        var decompressed = VbaRle.Decompress(container);

        // Assert
        Assert.Equal("AAAAAA", System.Text.Encoding.ASCII.GetString(decompressed));
    }

    [Fact]
    public void Decompress_UngueltigeSignatur_wirftInvalidData()
    {
        // Arrange
        byte[] container = [0x02, 0x03, 0xB0, 0x02, 0x41, 0x02, 0x00];

        // Act / Assert
        Assert.Throws<InvalidDataException>(() => VbaRle.Decompress(container));
    }

    [Fact]
    public void Decompress_UngueltigeChunkSignatur_wirftInvalidData()
    {
        // Arrange: Header-Signatur-Bits 12–14 auf 0b000 statt 0b011.
        byte[] container = [0x01, 0x03, 0x80, 0x02, 0x41, 0x02, 0x00];

        // Act / Assert
        Assert.Throws<InvalidDataException>(() => VbaRle.Decompress(container));
    }

    [Fact]
    public void Decompress_AbgeschnittenerChunk_wirftInvalidData()
    {
        // Arrange: Chunk-Größe beansprucht mehr Bytes als vorhanden.
        byte[] container = [0x01, 0xFF, 0x3F, 0x41];

        // Act / Assert
        Assert.Throws<InvalidDataException>(() => VbaRle.Decompress(container));
    }
}
