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
public class ReviewS1Fixture : IAsyncLifetime
{
    private const string SagaTableDdl = SagaStoreTestSchema.SagaTableDdl;

    private readonly Testcontainers.PostgreSql.PostgreSqlContainer _postgres =
        TestContainers.CreatePostgres();

    public PortalWebDbFactory Factory { get; private set; } = null!;

    public string ConnectionString => _postgres.GetConnectionString();

    /// <summary>Zusätzliche Konfiguration der WebUI-Fabrik (z. B. LiveStatus-Pollintervall).</summary>
    protected virtual IReadOnlyDictionary<string, string>? ExtraSettings => null;

    public async Task InitializeAsync()
    {
        await _postgres.StartAsync();
        // portal-DB und Saga-State-Store zeigen im Seam S1 auf denselben Container
        // (in Produktion getrennte Datenbanken, AppHost: workerDb als "sagastate").
        Factory = new PortalWebDbFactory(
            _postgres.GetConnectionString(),
            _postgres.GetConnectionString(),
            ExtraSettings);

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
        Guid jobId, string currentState, string submittedBy, DateTimeOffset receivedAt,
        Guid? signedArtifactId = null, string fileName = "test.xlsm")
    {
        const string insert = """
            INSERT INTO "analysis_saga"
                ("CorrelationId", "CurrentState", "SubmittedBy", "ArtifactId", "ContentSha256",
                 "OriginalFileName", "ContentType", "FileSizeBytes", "ReceivedAt", "SignedArtifactId")
            VALUES
                (@jobId, @state, @submittedBy, @artifactId, @sha256,
                 @fileName, @contentType, @fileSize, @receivedAt, @signedArtifactId)
            """;

        await using var connection = new NpgsqlConnection(ConnectionString);
        await connection.OpenAsync();
        await using var command = new NpgsqlCommand(insert, connection);
        command.Parameters.AddWithValue("jobId", jobId);
        command.Parameters.AddWithValue("state", currentState);
        command.Parameters.AddWithValue("submittedBy", submittedBy);
        command.Parameters.AddWithValue("artifactId", Guid.NewGuid());
        command.Parameters.AddWithValue("sha256", Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(jobId.ToByteArray())));
        command.Parameters.AddWithValue("fileName", fileName);
        command.Parameters.AddWithValue("contentType", "xlsm");
        command.Parameters.AddWithValue("fileSize", 12345L);
        command.Parameters.AddWithValue("receivedAt", receivedAt);
        command.Parameters.AddWithValue("signedArtifactId", (object?)signedArtifactId ?? DBNull.Value);
        await command.ExecuteNonQueryAsync();
    }

    /// <summary>
    /// Legt Upload-Zeile (analysis_jobs) und Blob (artifacts) der portal-DB an —
    /// Voraussetzung für Download-, Benachrichtigungs- und Status-Slices.
    /// </summary>
    public async Task<(Guid JobId, Guid ArtifactId)> SeedJobAsync(
        string submittedBy, string fileName, byte[] content, JobStatus status = JobStatus.Eingereicht,
        string? statusReason = null)
    {
        var jobId = Guid.NewGuid();
        var artifactId = Guid.NewGuid();
        var contentSha256 = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(content));

        await using var scope = Factory.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<PortalDbContext>();
        db.Artifacts.Add(new Artifact
        {
            ArtifactId = artifactId,
            Content = content,
            ContentSha256 = contentSha256,
        });
        db.AnalysisJobs.Add(new AnalysisJob
        {
            JobId = jobId,
            ArtifactId = artifactId,
            SubmittedBy = submittedBy,
            OriginalFileName = fileName,
            ContentType = "xlsm",
            FileSizeBytes = content.LongLength,
            ContentSha256 = contentSha256,
            Status = status,
            StatusReason = statusReason,
            CreatedAt = DateTimeOffset.UtcNow,
        });
        await db.SaveChangesAsync();
        return (jobId, artifactId);
    }

    /// <summary>Legt einen signierten Blob (neue Artefakt-Zeile ohne Upload-Zeile, T08) an.</summary>
    public async Task SeedSignedBlobAsync(Guid signedArtifactId, byte[] content)
    {
        await using var scope = Factory.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<PortalDbContext>();
        db.Artifacts.Add(new Artifact
        {
            ArtifactId = signedArtifactId,
            Content = content,
            ContentSha256 = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(content)),
        });
        await db.SaveChangesAsync();
    }

    /// <summary>Simuliert einen Saga-Übergang direkt im State-Store (Live-Status-Push).</summary>
    public async Task UpdateSagaStateAsync(Guid jobId, string currentState, Guid? signedArtifactId = null)
    {
        const string update = """
            UPDATE "analysis_saga"
            SET "CurrentState" = @state, "SignedArtifactId" = @signedArtifactId
            WHERE "CorrelationId" = @jobId
            """;

        await using var connection = new NpgsqlConnection(ConnectionString);
        await connection.OpenAsync();
        await using var command = new NpgsqlCommand(update, connection);
        command.Parameters.AddWithValue("jobId", jobId);
        command.Parameters.AddWithValue("state", currentState);
        command.Parameters.AddWithValue("signedArtifactId", (object?)signedArtifactId ?? DBNull.Value);
        await command.ExecuteNonQueryAsync();
    }

    /// <summary>
    /// Legt einen Audit-Eintrag (Roheinfügung, Hash-Kette nicht relevant für diese
    /// Slices) an — Ereignisquelle für Status-Anreicherung, Benachrichtigungen und
    /// den Signatur-Zeitstempel des Downloads.
    /// </summary>
    public async Task SeedAuditAsync(
        Guid jobId, string category, string ereignis, string aktor,
        DateTimeOffset occurredAt, string? detail = null)
    {
        const string insert = """
            INSERT INTO "audit_trail"
                ("JobId", "OccurredAt", "Category", "Ereignis", "Aktor", "Detail", "PrevHash", "EntryHash")
            VALUES
                (@jobId, @occurredAt, @category, @ereignis, @aktor, @detail, @prevHash, @entryHash)
            """;

        var hash = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(Guid.NewGuid().ToByteArray())).ToLowerInvariant();
        await using var connection = new NpgsqlConnection(ConnectionString);
        await connection.OpenAsync();
        await using var command = new NpgsqlCommand(insert, connection);
        command.Parameters.AddWithValue("jobId", jobId);
        command.Parameters.AddWithValue("occurredAt", occurredAt);
        command.Parameters.AddWithValue("category", category);
        command.Parameters.AddWithValue("ereignis", ereignis);
        command.Parameters.AddWithValue("aktor", aktor);
        command.Parameters.AddWithValue("detail", (object?)detail ?? DBNull.Value);
        command.Parameters.AddWithValue("prevHash", hash);
        command.Parameters.AddWithValue("entryHash", hash);
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
