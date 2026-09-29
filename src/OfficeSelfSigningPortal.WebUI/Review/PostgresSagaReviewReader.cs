using Npgsql;
using Ossp.Contracts;

namespace OfficeSelfSigningPortal.WebUI.Review;

/// <summary>
/// Npgsql-Implementierung von <see cref="ISagaReviewReader"/> (read-only).
/// Tabellen-/Spaltennamen entsprechen der WorkerService-Migration
/// (<c>analysis_saga."CorrelationId"/"CurrentState"/…</c>); die WHERE-Konstanten
/// sind fixe Anhang-B-Zustandsnamen — kein Nutzer-Input im SQL.
/// </summary>
public sealed class PostgresSagaReviewReader(string? connectionString) : ISagaReviewReader
{
    // Parametrisiertes Raw SQL (CONVENTIONS §6): ausschließlich lesend, Abweichung
    // vom EF-Pfad begründet (kein EF-Kontext über das fremde WorkerService-Schema).
    private const string OpenReviewsQuery = """
        SELECT "CorrelationId", "CurrentState", "SubmittedBy", "OriginalFileName",
               "ContentType", "FileSizeBytes", "ReceivedAt", "SignedArtifactId"
        FROM "analysis_saga"
        WHERE "CurrentState" IN ('ReviewAusstehend', 'RueckfrageAusstehend')
        ORDER BY "ReceivedAt" ASC
        """;

    private const string VorgangQuery = """
        SELECT "CorrelationId", "CurrentState", "SubmittedBy", "OriginalFileName",
               "ContentType", "FileSizeBytes", "ReceivedAt", "SignedArtifactId"
        FROM "analysis_saga"
        WHERE "CorrelationId" = @jobId
        """;

    public async Task<IReadOnlyList<SagaVorgangInfo>> GetOpenReviewsAsync(CancellationToken cancellationToken)
    {
        await using var connection = await OpenConnectionAsync(cancellationToken);
        await using var command = new NpgsqlCommand(OpenReviewsQuery, connection);

        var result = new List<SagaVorgangInfo>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            result.Add(ReadVorgang(reader));
        }

        return result;
    }

    public async Task<SagaVorgangInfo?> GetVorgangAsync(Guid jobId, CancellationToken cancellationToken)
    {
        await using var connection = await OpenConnectionAsync(cancellationToken);
        await using var command = new NpgsqlCommand(VorgangQuery, connection);
        command.Parameters.AddWithValue("jobId", jobId);

        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        return await reader.ReadAsync(cancellationToken) ? ReadVorgang(reader) : null;
    }

    private async Task<NpgsqlConnection> OpenConnectionAsync(CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(connectionString))
        {
            throw new InvalidOperationException(
                "Connection String 'sagastate' fehlt — bitte Aspire-AppHost oder Konfiguration prüfen.");
        }

        var connection = new NpgsqlConnection(connectionString);
        await connection.OpenAsync(cancellationToken);
        return connection;
    }

    private static SagaVorgangInfo ReadVorgang(NpgsqlDataReader reader)
        => new(
            reader.GetGuid(0),
            reader.GetString(1),
            reader.GetString(2),
            reader.GetString(3),
            reader.GetString(4),
            reader.GetInt64(5),
            reader.GetFieldValue<DateTimeOffset>(6),
            reader.IsDBNull(7) ? null : reader.GetGuid(7));
}
