using Microsoft.EntityFrameworkCore;

namespace Ossp.Audit;

/// <summary>
/// DbContext des Audit-Trails. Schreib- und Lesepfad aller Services auf die
/// gemeinsame append-only Tabelle <c>audit_trail</c> (portal-DB); Migrations
/// gehören zu diesem Kontext (ein DbContext pro fachlichem Kontext, CONVENTIONS §2).
/// Die <c>audit_chain_checkpoints</c>-Tabelle (Ticket 38, REQ-19) speichert die
/// sanctioned Lösch-Grenzen der Audit-Retention, damit die Hash-Kette nach
/// physischer Löschung alter Einträge weiterhin verifizierbar bleibt.
/// </summary>
public class AuditDbContext(DbContextOptions<AuditDbContext> options) : DbContext(options)
{
    public DbSet<AuditEntry> AuditEntries => Set<AuditEntry>();

    public DbSet<AuditChainCheckpoint> ChainCheckpoints => Set<AuditChainCheckpoint>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.ApplyConfiguration(new AuditEntryMap());
        modelBuilder.ApplyConfiguration(new AuditChainCheckpointMap());
    }
}
