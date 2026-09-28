using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;
using Microsoft.Extensions.Configuration;

namespace OfficeSelfSigningPortal.SigningService.Data;

/// <summary>
/// Design-Time-Factory für dotnet ef. Der Connection String kommt ausschließlich
/// aus User-Secrets oder Umgebungsvariablen — niemals aus dem Repository (REQ-24).
/// </summary>
public sealed class SigningDbContextDesignTimeFactory : IDesignTimeDbContextFactory<SigningDbContext>
{
    public SigningDbContext CreateDbContext(string[] args)
    {
        var config = new ConfigurationBuilder()
            .AddUserSecrets<SigningDbContextDesignTimeFactory>(optional: true)
            .AddEnvironmentVariables()
            .Build();

        var connectionString = config.GetConnectionString("signing")
            ?? throw new InvalidOperationException(
                "Connection String 'signing' fehlt. Per User-Secret 'ConnectionStrings:signing' " +
                "oder Umgebungsvariable setzen — siehe docs/development-setup.md.");

        var options = new DbContextOptionsBuilder<SigningDbContext>()
            .UseNpgsql(connectionString)
            .Options;

        return new SigningDbContext(options);
    }
}
