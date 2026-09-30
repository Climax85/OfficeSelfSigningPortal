using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using OfficeSelfSigningPortal.Tests.Support;
using OfficeSelfSigningPortal.WebUI.Data;
using Ossp.Audit;
using Xunit;

namespace OfficeSelfSigningPortal.Tests.Ingestion;

/// <summary>
/// Startet PostgreSQL-Testcontainer + WebUI (Seam S1) und spielt das EF-Migrations-Schema ein.
/// Geteilt über alle S1-Persistenztests einer Collection.
/// </summary>
public sealed class IngestionS1Fixture : IAsyncLifetime
{
    private readonly Testcontainers.PostgreSql.PostgreSqlContainer _postgres =
        TestContainers.CreatePostgres();

    public PortalWebDbFactory Factory { get; private set; } = null!;

    /// <summary>Liefert den Body der jüngsten Outbox-Nachricht eines Typs (Seam S1, Diagnose/Assert).</summary>
    public async Task<string?> GetOutboxMessageBodyAsync(Guid jobId, string messageTypeSuffix)
    {
        const string query = """
            SELECT "Body" FROM "OutboxMessage"
            WHERE "MessageType" LIKE @suffix AND "Body" LIKE @jobId
            ORDER BY "SequenceNumber" DESC LIMIT 1
            """;

        await using var connection = new Npgsql.NpgsqlConnection(_postgres.GetConnectionString());
        await connection.OpenAsync();
        await using var command = new Npgsql.NpgsqlCommand(query, connection);
        command.Parameters.AddWithValue("suffix", $"%{messageTypeSuffix}");
        command.Parameters.AddWithValue("jobId", $"%{jobId}%");
        return await command.ExecuteScalarAsync() as string;
    }

    /// <summary>Prüft, dass eine Outbox-Nachricht eines Typs einen Body-Fragment führt (Seam S1).</summary>
    public async Task<bool> OutboxMessageBodyContainsAsync(Guid jobId, string messageTypeSuffix, string bodyFragment)
    {
        var body = await GetOutboxMessageBodyAsync(jobId, messageTypeSuffix);
        return body?.Contains(bodyFragment, StringComparison.Ordinal) == true;
    }

    public async Task InitializeAsync()
    {
        await _postgres.StartAsync();
        // Der Status-Endpunkt liest den Saga-State-Store (T09) — im Seam S1 zeigt
        // 'sagastate' auf denselben Container (vgl. ReviewS1Fixture).
        Factory = new PortalWebDbFactory(_postgres.GetConnectionString(), _postgres.GetConnectionString());

        await using var scope = Factory.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<PortalDbContext>();
        await db.Database.MigrateAsync();

        // Upload schreibt seit Ticket 06 Audit-Einträge (REQ-18) — Audit-Schema mitspielen.
        var auditDb = scope.ServiceProvider.GetRequiredService<AuditDbContext>();
        await auditDb.Database.MigrateAsync();

        await using var connection = new Npgsql.NpgsqlConnection(_postgres.GetConnectionString());
        await connection.OpenAsync();
        await using var command = new Npgsql.NpgsqlCommand(SagaStoreTestSchema.SagaTableDdl, connection);
        await command.ExecuteNonQueryAsync();
    }

    public async Task DisposeAsync()
    {
        await Factory.DisposeAsync();
        await _postgres.DisposeAsync();
    }
}

[CollectionDefinition(IngestionS1Collection.CollectionName)]
public sealed class IngestionS1Collection : ICollectionFixture<IngestionS1Fixture>
{
    public const string CollectionName = "Ingestion S1";
}
