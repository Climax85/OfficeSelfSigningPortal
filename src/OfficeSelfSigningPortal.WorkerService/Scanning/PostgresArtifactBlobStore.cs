using Npgsql;

namespace OfficeSelfSigningPortal.WorkerService.Scanning;

/// <summary>
/// Read-only Zugriff auf die Artefakt-Tabelle der Portal-DB über Npgsql (ADO.NET).
/// Bewusst kein zweiter EF-Core-Kontext über ein fremdes Schema: eine parametrisierte
/// Abfrage (CONVENTIONS §6) auf die von der WebUI-Migration geführte Tabelle — der
/// WorkerService erhält keinen Schreibpfad und keine Mapping-Duplikate.
/// Tabellen-/Spaltennamen entsprechen der WebUI-Migration
/// (<c>artifacts."ArtifactId"/"Content"/"ContentSha256"</c>).
/// </summary>
public sealed class PostgresArtifactBlobStore(string connectionString) : IArtifactBlobStore
{
    // Parametrisiertes Raw SQL (kein String-Interpolate): ausschließlich lesend,
    // Abweichung vom EF-Pfad begründet + review-freigegeben (CONVENTIONS §6).
    private const string BlobQuery = """
        SELECT "Content", "ContentSha256"
        FROM "artifacts"
        WHERE "ArtifactId" = @artifactId
        """;

    public async Task<ArtifactBlob?> ReadAsync(Guid artifactId, CancellationToken cancellationToken)
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

        return new ArtifactBlob(
            Content: (byte[])reader["Content"],
            ContentSha256: (string)reader["ContentSha256"]);
    }
}
