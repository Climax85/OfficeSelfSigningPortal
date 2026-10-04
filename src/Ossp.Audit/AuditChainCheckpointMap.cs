using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Ossp.Audit;

/// <summary>Mapping der Retention-Checkpoint-Tabelle (REQ-19, Ticket 38, Audit-Retention 1 Jahr).</summary>
public sealed class AuditChainCheckpointMap : IEntityTypeConfiguration<AuditChainCheckpoint>
{
    public void Configure(EntityTypeBuilder<AuditChainCheckpoint> entity)
    {
        entity.ToTable("audit_chain_checkpoints");
        entity.HasKey(x => x.Id);
        entity.Property(x => x.LastDeletedEntryHash).HasMaxLength(64).IsFixedLength();
        entity.Property(x => x.Aktor).HasMaxLength(256);
        entity.Property(x => x.Reason).HasMaxLength(128);
        // Lookup für die Admin-Verifikation: pro Aufruf wird der erste
        // Eintrag eines Vorgangs gegen diese Tabelle geprüft.
        entity.HasIndex(x => x.LastDeletedEntryHash);
    }
}
