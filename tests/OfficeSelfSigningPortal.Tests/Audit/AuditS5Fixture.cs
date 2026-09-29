using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using OfficeSelfSigningPortal.Tests.Support;
using OfficeSelfSigningPortal.WebUI.Data;
using Ossp.Audit;
using Testcontainers.PostgreSql;
using Xunit;

namespace OfficeSelfSigningPortal.Tests.Audit;

/// <summary>
/// Seam S5 (Persistenz): PostgreSQL-Testcontainer als 'portal'-Datenbank, daran das
/// AuditTrail-Schema (Ossp.Audit, Migrationseigner) und die WebUI (Seam S1) verdrahtet.
/// Geteilt über alle Audit-Trail-Tests einer Collection.
/// </summary>
public sealed class AuditS5Fixture : IAsyncLifetime
{
    private readonly PostgreSqlContainer _postgres = TestContainers.CreatePostgres();
    private ServiceProvider _auditServices = null!;

    public PortalWebDbFactory Factory { get; private set; } = null!;

    public string ConnectionString => _postgres.GetConnectionString();

    public IAuditTrailWriter Writer => _auditServices.GetRequiredService<IAuditTrailWriter>();

    public AuditDbContext CreateAuditDbContext() =>
        _auditServices.GetRequiredService<IDbContextFactory<AuditDbContext>>().CreateDbContext();

    public async Task InitializeAsync()
    {
        await _postgres.StartAsync();

        var services = new ServiceCollection();
        services.AddLogging();
        services.AddAuditTrail(_postgres.GetConnectionString());
        _auditServices = services.BuildServiceProvider(true);

        await using var db = CreateAuditDbContext();
        await db.Database.MigrateAsync();

        Factory = new PortalWebDbFactory(_postgres.GetConnectionString());

        // Upload-Endpunkt (Outbox/AnalysisJobs) und Audit-Trail gleichermaßen migrieren.
        await using var scope = Factory.Services.CreateAsyncScope();
        var portalDb = scope.ServiceProvider.GetRequiredService<PortalDbContext>();
        await portalDb.Database.MigrateAsync();
    }

    public async Task DisposeAsync()
    {
        if (_auditServices is not null)
        {
            await _auditServices.DisposeAsync();
        }

        if (Factory is not null)
        {
            await Factory.DisposeAsync();
        }

        await _postgres.DisposeAsync();
    }
}

[CollectionDefinition(AuditS5Collection.CollectionName)]
public sealed class AuditS5Collection : ICollectionFixture<AuditS5Fixture>
{
    public const string CollectionName = "Audit S5";
}
