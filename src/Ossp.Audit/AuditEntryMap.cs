using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Ossp.Audit;

/// <summary>Mapping der append-only Audit-Tabelle (portal-DB, Migrationseigner Ossp.Audit).</summary>
public sealed class AuditEntryMap : IEntityTypeConfiguration<AuditEntry>
{
    public void Configure(EntityTypeBuilder<AuditEntry> entity)
    {
        entity.ToTable("audit_trail");
        entity.HasKey(x => x.Id);
        entity.Property(x => x.Category).HasMaxLength(32);
        entity.Property(x => x.Ereignis).HasMaxLength(512);
        entity.Property(x => x.Aktor).HasMaxLength(256);
        entity.Property(x => x.Detail);
        entity.Property(x => x.PrevHash).HasMaxLength(64).IsFixedLength();
        entity.Property(x => x.EntryHash).HasMaxLength(64).IsFixedLength();
        entity.HasIndex(x => x.JobId);
        // Lookup für die Vorgänger-Verifikation des ersten Eintrags eines Vorgangs
        // (global verkettete Tabelle, AK-07).
        entity.HasIndex(x => x.EntryHash);
    }
}
