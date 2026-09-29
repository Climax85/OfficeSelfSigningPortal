using Microsoft.EntityFrameworkCore;

namespace Ossp.Audit;

/// <summary>
/// DbContext des Audit-Trails. Schreib- und Lesepfad aller Services auf die
/// gemeinsame append-only Tabelle <c>audit_trail</c> (portal-DB); Migrations
/// gehören zu diesem Kontext (ein DbContext pro fachlichem Kontext, CONVENTIONS §2).
/// </summary>
public class AuditDbContext(DbContextOptions<AuditDbContext> options) : DbContext(options)
{
    public DbSet<AuditEntry> AuditEntries => Set<AuditEntry>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
        => modelBuilder.ApplyConfiguration(new AuditEntryMap());
}
