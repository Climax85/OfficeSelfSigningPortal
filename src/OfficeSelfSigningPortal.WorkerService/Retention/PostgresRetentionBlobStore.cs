using Npgsql;

namespace OfficeSelfSigningPortal.WorkerService.Retention;

/// <summary>
/// Löscht Artefakt-Zeilen der Portal-DB über Npgsql (ADO.NET) — analog zum
/// read-only Zugriff des Scan-Pfads (<see cref="Scanning.PostgresArtifactBlobStore"/>).
/// Bewusst kein zweiter EF-Core-Kontext über ein fremdes Schema: der WorkerService
/// führt keinen <c>PortalDbContext</c> (fachlicher Kontext der WebUI, CONVENTIONS §2).
/// Parametrisiertes Raw SQL (Array-Parameter, kein String-Interpolate) —
/// Abweichung vom EF-Pfad wie beim Scan-Lesepfad begründet (CONVENTIONS §6).
/// Tabellen-/Spaltennamen entsprechen der WebUI-Migration (<c>artifacts."ArtifactId"</c>).
/// </summary>
public sealed class PostgresRetentionBlobStore(string connectionString) : IRetentionBlobStore
{
    private const string DeleteCommand = """
        DELETE FROM "artifacts"
        WHERE "ArtifactId" = ANY(@artifactIds)
        """;

    public async Task<int> DeleteAsync(IReadOnlyCollection<Guid> artifactIds, CancellationToken cancellationToken)
    {
        if (artifactIds.Count == 0)
        {
            return 0;
        }

        await using var connection = new NpgsqlConnection(connectionString);
        await connection.OpenAsync(cancellationToken);

        await using var command = new NpgsqlCommand(DeleteCommand, connection);
        command.Parameters.AddWithValue("artifactIds", artifactIds.ToArray());

        return await command.ExecuteNonQueryAsync(cancellationToken);
    }
}
