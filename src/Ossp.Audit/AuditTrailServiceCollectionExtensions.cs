using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace Ossp.Audit;

/// <summary>DI-Verdrahtung des Audit-Trails (Append-only, SHA-256-Hash-Kette).</summary>
public static class AuditTrailServiceCollectionExtensions
{
    /// <summary>
    /// Registriert <see cref="AuditDbContext"/>, dessen Factory und den
    /// <see cref="IAuditTrailWriter"/> (Singleton — die Serialisierung der Appends
    /// übernimmt der Datenbank-Advisory-Lock, nicht die Instanz). Die Options werden
    /// als Singleton geführt, damit der Singleton-Factory unter Scope-Validierung
    /// auflösbar bleibt; der Kontext selbst bleibt Scoped.
    /// </summary>
    public static IServiceCollection AddAuditTrail(this IServiceCollection services, string connectionString)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(connectionString);

        services.AddDbContextFactory<AuditDbContext>(options => options.UseNpgsql(connectionString));
        services.AddDbContext<AuditDbContext>(ServiceLifetime.Scoped, ServiceLifetime.Singleton);
        services.AddSingleton<IAuditTrailWriter, AuditTrailWriter>();
        return services;
    }
}
