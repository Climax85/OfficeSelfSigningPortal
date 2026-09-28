using Npgsql;
using Ossp.Contracts;

namespace OfficeSelfSigningPortal.SigningService.Messaging;

/// <summary>
/// Read-only Zugriff auf den Saga-State-Store über Npgsql (ADO.NET). Bewusst kein
/// zweiter EF-Core-Kontext über ein fremdes Schema: eine parametrisierte Abfrage
/// (CONVENTIONS §6) auf die von der Saga-Migration geführte Tabelle — das
/// SigningService erhält keinen Schreibpfad und keine Mapping-Duplikate.
/// Tabellen-/Spaltennamen entsprechen der WorkerService-Migration
/// (<c>analysis_saga."CorrelationId"/"CurrentState"</c>).
/// </summary>
public sealed class PostgresSagaStateReader(string connectionString) : ISagaStateReader
{
    // Parametrisiertes Raw SQL (kein String-Interpolate): ausschließlich lesend,
    // Abweichung vom EF-Pfad begründet + review-freigegeben (CONVENTIONS §6, TM-19).
    private const string StateQuery = """
        SELECT "CurrentState"
        FROM "analysis_saga"
        WHERE "CorrelationId" = @jobId
        """;

    public async Task<string?> GetSagaStateAsync(Guid jobId, CancellationToken cancellationToken)
    {
        await using var connection = new NpgsqlConnection(connectionString);
        await connection.OpenAsync(cancellationToken);

        await using var command = new NpgsqlCommand(StateQuery, connection);
        command.Parameters.AddWithValue("jobId", jobId);

        var result = await command.ExecuteScalarAsync(cancellationToken);
        return result is string state ? state : null;
    }
}
