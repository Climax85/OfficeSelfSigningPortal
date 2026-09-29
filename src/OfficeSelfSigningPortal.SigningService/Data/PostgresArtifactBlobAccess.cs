using System.Security.Cryptography;
using Npgsql;

namespace OfficeSelfSigningPortal.SigningService.Data;

/// <summary>
/// Artefakt-Zugriff über Npgsql (ADO.NET) auf die Portal-DB. Bewusst kein zweiter EF-Core-
/// Kontext über ein fremdes Schema: parametrisierte Statements (CONVENTIONS §6) auf der von
/// der WebUI-Migration geführten Tabelle — etabliertes PostgresSagaStateReader-/
/// PostgresArtifactBlobStore-Muster, review-freigegeben (T04/T05).
/// </summary>
public sealed class PostgresArtifactBlobAccess(string connectionString) : IArtifactBlobAccess
{
    // Parametrisiertes Raw SQL (kein String-Interpolate): Lesen + ein INSERT für den
    // signierten Blob; Abweichung vom EF-Pfad begründet (fremdes Schema, CONVENTIONS §6).
    private const string BlobQuery = """
        SELECT "Content", "ContentSha256"
        FROM "artifacts"
        WHERE "ArtifactId" = @artifactId
        """;

    private const string InsertSignedBlobCommand = """
        INSERT INTO "artifacts" ("ArtifactId", "Content", "ContentSha256")
        VALUES (@artifactId, @content, @contentSha256)
        """;

    public async Task<ArtifactBlobContent?> ReadAsync(Guid artifactId, CancellationToken cancellationToken)
    {
        await using var connection = new NpgsqlConnection(connectionString);
        await connection.OpenAsync(cancellationToken);

        await using var command = new NpgsqlCommand(BlobQuery, connection);
        command.Parameters.AddWithValue("artifactId", artifactId);

        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken))
        {
            return null;
        }

        return new ArtifactBlobContent(
            Content: (byte[])reader["Content"],
            ContentSha256: (string)reader["ContentSha256"]);
    }

    public async Task<string> StoreSignedAsync(Guid artifactId, byte[] content, CancellationToken cancellationToken)
    {
        var contentSha256 = Convert.ToHexString(SHA256.HashData(content));

        await using var connection = new NpgsqlConnection(connectionString);
        await connection.OpenAsync(cancellationToken);

        await using var command = new NpgsqlCommand(InsertSignedBlobCommand, connection);
        command.Parameters.AddWithValue("artifactId", artifactId);
        command.Parameters.AddWithValue("content", content);
        command.Parameters.AddWithValue("contentSha256", contentSha256);

        await command.ExecuteNonQueryAsync(cancellationToken);
        return contentSha256;
    }
}
