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
