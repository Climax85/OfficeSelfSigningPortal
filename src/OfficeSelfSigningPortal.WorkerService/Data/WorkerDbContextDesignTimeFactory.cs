using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;
using Microsoft.Extensions.Configuration;

namespace OfficeSelfSigningPortal.WorkerService.Data;

/// <summary>
/// Design-Time-Factory für dotnet ef. Der Connection String kommt ausschließlich
/// aus User-Secrets oder Umgebungsvariablen — niemals aus dem Repository (REQ-24).
/// </summary>
public sealed class WorkerDbContextDesignTimeFactory : IDesignTimeDbContextFactory<WorkerDbContext>
{
    public WorkerDbContext CreateDbContext(string[] args)
    {
        var config = new ConfigurationBuilder()
            .AddUserSecrets<WorkerDbContextDesignTimeFactory>(optional: true)
            .AddEnvironmentVariables()
            .Build();

        var connectionString = config.GetConnectionString("worker")
            ?? throw new InvalidOperationException(
                "Connection String 'worker' fehlt. Per User-Secret 'ConnectionStrings:worker' " +
                "oder Umgebungsvariable setzen — siehe docs/development-setup.md.");

        var options = new DbContextOptionsBuilder<WorkerDbContext>()
            .UseNpgsql(connectionString)
            .Options;

        return new WorkerDbContext(options);
    }
}
