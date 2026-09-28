using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;
using Microsoft.Extensions.Configuration;

namespace OfficeSelfSigningPortal.WebUI.Data;

/// <summary>
/// Design-Time-Factory für dotnet ef. Der Connection String kommt ausschließlich
/// aus User-Secrets oder Umgebungsvariablen — niemals aus dem Repository (REQ-24).
/// </summary>
public sealed class PortalDbContextDesignTimeFactory : IDesignTimeDbContextFactory<PortalDbContext>
{
    public PortalDbContext CreateDbContext(string[] args)
    {
        var config = new ConfigurationBuilder()
            .AddUserSecrets<PortalDbContextDesignTimeFactory>(optional: true)
            .AddEnvironmentVariables()
            .Build();

        var connectionString = config.GetConnectionString("portal")
            ?? throw new InvalidOperationException(
                "Connection String 'portal' fehlt. Per User-Secret 'ConnectionStrings:portal' " +
                "oder Umgebungsvariable setzen — siehe docs/development-setup.md.");

        var options = new DbContextOptionsBuilder<PortalDbContext>()
            .UseNpgsql(connectionString)
            .Options;

        return new PortalDbContext(options);
    }
}
