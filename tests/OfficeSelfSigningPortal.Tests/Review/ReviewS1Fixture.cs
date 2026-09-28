using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;
using OfficeSelfSigningPortal.Tests.Support;
using OfficeSelfSigningPortal.WebUI.Data;
using Ossp.Audit;
using Xunit;

namespace OfficeSelfSigningPortal.Tests.Review;

/// <summary>
/// Seam S1 für das Review-API (Ticket 07): PostgreSQL-Testcontainer + WebUI mit
/// Test-AuthHandler. Die <c>analysis_saga</c>-Tabelle wird per DDL gespiegelt
/// (Spiegelung der WorkerService-Migration — der WebUI-Reader ist bewusst
/// schema-parallel zum SigningService, kein EF-Pfad über ein fremdes Schema).
/// </summary>
public sealed class ReviewS1Fixture : IAsyncLifetime
{
    private const string SagaTableDdl = """
        CREATE TABLE "analysis_saga" (
            "CorrelationId" uuid NOT NULL PRIMARY KEY,
            "CurrentState" character varying(64) NOT NULL,
            "SubmittedBy" character varying(256) NOT NULL,
            "ArtifactId" uuid NOT NULL,
            "ContentSha256" character varying(64) NOT NULL,
            "OriginalFileName" character varying(512) NOT NULL,
            "ContentType" character varying(16) NOT NULL,
            "FileSizeBytes" bigint NOT NULL,
            "ReceivedAt" timestamp with time zone NOT NULL
        );
        CREATE INDEX "IX_analysis_saga_ReceivedAt" ON "analysis_saga" ("ReceivedAt");
        """;

    private readonly Testcontainers.PostgreSql.PostgreSqlContainer _postgres =
        TestContainers.CreatePostgres();

    public PortalWebDbFactory Factory { get; private set; } = null!;

    public string ConnectionString => _postgres.GetConnectionString();

    public async Task InitializeAsync()
    {
        await _postgres.StartAsync();
        // portal-DB und Saga-State-Store zeigen im Seam S1 auf denselben Container
        // (in Produktion getrennte Datenbanken, AppHost: workerDb als "sagastate").
        Factory = new PortalWebDbFactory(_postgres.GetConnectionString(), _postgres.GetConnectionString());

        await using var scope = Factory.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<PortalDbContext>();
        await db.Database.MigrateAsync();

        var auditDb = scope.ServiceProvider.GetRequiredService<AuditDbContext>();
        await auditDb.Database.MigrateAsync();

        await using var connection = new NpgsqlConnection(ConnectionString);
        await connection.OpenAsync();
        await using var command = new NpgsqlCommand(SagaTableDdl, connection);
        await command.ExecuteNonQueryAsync();
    }

    public async Task DisposeAsync()
    {
        await Factory.DisposeAsync();
        await _postgres.DisposeAsync();
    }

    /// <summary>Legt eine Saga-Zeile (Spiegelung des persistierten Vorgangsstatus) an.</summary>
    public async Task SeedSagaAsync(
        Guid jobId, string currentState, string submittedBy, DateTimeOffset receivedAt)
    {
        const string insert = """
            INSERT INTO "analysis_saga"
                ("CorrelationId", "CurrentState", "SubmittedBy", "ArtifactId", "ContentSha256",
                 "OriginalFileName", "ContentType", "FileSizeBytes", "ReceivedAt")
            VALUES
                (@jobId, @state, @submittedBy, @artifactId, @sha256,
                 @fileName, @contentType, @fileSize, @receivedAt)
            """;

        await using var connection = new NpgsqlConnection(ConnectionString);
        await connection.OpenAsync();
        await using var command = new NpgsqlCommand(insert, connection);
        command.Parameters.AddWithValue("jobId", jobId);
        command.Parameters.AddWithValue("state", currentState);
        command.Parameters.AddWithValue("submittedBy", submittedBy);
        command.Parameters.AddWithValue("artifactId", Guid.NewGuid());
        command.Parameters.AddWithValue("sha256", Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(jobId.ToByteArray())));
        command.Parameters.AddWithValue("fileName", "test.xlsm");
        command.Parameters.AddWithValue("contentType", "xlsm");
        command.Parameters.AddWithValue("fileSize", 12345L);
        command.Parameters.AddWithValue("receivedAt", receivedAt);
        await command.ExecuteNonQueryAsync();
    }

    /// <summary>Liest den zuletzt gestagten Outbox-Body eines Nachrichtentyps (Assertion auf Staging).</summary>
    public async Task<string?> GetLatestOutboxBodyAsync(string messageTypeSuffix)
    {
        const string query = """
            SELECT "Body" FROM "OutboxMessage"
            WHERE "MessageType" LIKE @suffix
            ORDER BY "SequenceNumber" DESC
            LIMIT 1
            """;

        await using var connection = new NpgsqlConnection(ConnectionString);
        await connection.OpenAsync();
        await using var command = new NpgsqlCommand(query, connection);
        command.Parameters.AddWithValue("suffix", $"%{messageTypeSuffix}");
        var result = await command.ExecuteScalarAsync();
        return result as string;
    }

    /// <summary>
    /// Zählt gestagte Outbox-Nachrichten eines Typs für einen Vorgang (Negativ-Assertions:
    /// eine abgewiesene Entscheidung darf nichts stagen).
    /// </summary>
    public async Task<long> CountOutboxMessagesForJobAsync(Guid jobId, string messageTypeSuffix)
    {
        const string query = """
            SELECT COUNT(*) FROM "OutboxMessage"
            WHERE "MessageType" LIKE @suffix AND "Body" LIKE @jobId
            """;

        await using var connection = new NpgsqlConnection(ConnectionString);
        await connection.OpenAsync();
        await using var command = new NpgsqlCommand(query, connection);
        command.Parameters.AddWithValue("suffix", $"%{messageTypeSuffix}");
        command.Parameters.AddWithValue("jobId", $"%{jobId}%");
        return (long)(await command.ExecuteScalarAsync() ?? 0L);
    }

    /// <summary>Zählt Audit-Einträge eines Vorgangs in einer Kategorie (guard/review).</summary>
    public async Task<long> CountAuditEntriesAsync(Guid jobId, string category)
    {
        const string query = """
            SELECT COUNT(*) FROM "audit_trail" WHERE "JobId" = @jobId AND "Category" = @category
            """;

        await using var connection = new NpgsqlConnection(ConnectionString);
        await connection.OpenAsync();
        await using var command = new NpgsqlCommand(query, connection);
        command.Parameters.AddWithValue("jobId", jobId);
        command.Parameters.AddWithValue("category", category);
        return (long)(await command.ExecuteScalarAsync() ?? 0L);
    }
}
