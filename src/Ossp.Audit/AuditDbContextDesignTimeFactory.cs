using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;
using Microsoft.Extensions.Configuration;

namespace Ossp.Audit;

/// <summary>
/// Design-Time-Factory für dotnet ef. Der Connection String kommt ausschließlich
/// aus User-Secrets oder Umgebungsvariablen — niemals aus dem Repository (REQ-24).
/// </summary>
public sealed class AuditDbContextDesignTimeFactory : IDesignTimeDbContextFactory<AuditDbContext>
{
    public AuditDbContext CreateDbContext(string[] args)
    {
        var config = new ConfigurationBuilder()
            .AddUserSecrets<AuditDbContextDesignTimeFactory>(optional: true)
            .AddEnvironmentVariables()
            .Build();

        var connectionString = config.GetConnectionString("audit")
            ?? throw new InvalidOperationException(
                "Connection String 'audit' fehlt. Per User-Secret 'ConnectionStrings:audit' " +
                "oder Umgebungsvariable setzen — siehe docs/development-setup.md.");

        var options = new DbContextOptionsBuilder<AuditDbContext>()
            .UseNpgsql(connectionString)
            .Options;

        return new AuditDbContext(options);
    }
}
