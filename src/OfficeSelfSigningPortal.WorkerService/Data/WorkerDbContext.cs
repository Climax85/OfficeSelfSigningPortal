using MassTransit;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using OfficeSelfSigningPortal.WorkerService.Saga;

namespace OfficeSelfSigningPortal.WorkerService.Data;

/// <summary>
/// DbContext des WorkerService (fachlicher Kontext Analyse/Saga). Hält die
/// Saga-Instanz, die Übergangs-Audit-Einträge (REQ-18; Hash-Kette liefert Ticket 06)
/// und die MassTransit-Outbox-Tabellen (REQ-11, TM-06).
/// </summary>
public class WorkerDbContext(DbContextOptions<WorkerDbContext> options) : DbContext(options)
{
    public DbSet<AnalysisSagaState> SagaStates => Set<AnalysisSagaState>();

    public DbSet<SagaAuditEntry> SagaAuditEntries => Set<SagaAuditEntry>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<AnalysisSagaState>(ConfigureAnalysisSagaState);
        modelBuilder.ApplyConfiguration(new SagaAuditEntryMap());
        modelBuilder.AddOutboxStateEntity();
        modelBuilder.AddOutboxMessageEntity();
    }

    /// <summary>MassTransit-EF-Persistenz der Saga (verbindliche Zustandsnamen, Anhang B).</summary>
    private static void ConfigureAnalysisSagaState(EntityTypeBuilder<AnalysisSagaState> entity)
    {
        entity.ToTable("analysis_saga");
        entity.HasKey(x => x.CorrelationId);
        entity.Property(x => x.CurrentState).HasMaxLength(64);
        entity.Property(x => x.SubmittedBy).HasMaxLength(256);
        entity.Property(x => x.OriginalFileName).HasMaxLength(512);
        entity.Property(x => x.ContentType).HasMaxLength(16);
        entity.Property(x => x.ContentSha256).HasMaxLength(64);
        entity.HasIndex(x => x.ReceivedAt);
    }
}

/// <summary>Übergangs-Audit (Anhang B, REQ-18) — Hash-Kette und Append-only erzeugt Ticket 06.</summary>
public sealed class SagaAuditEntryMap : IEntityTypeConfiguration<SagaAuditEntry>
{
    public void Configure(EntityTypeBuilder<SagaAuditEntry> entity)
    {
        entity.ToTable("saga_audit_entries");
        entity.HasKey(x => x.Id);
        entity.Property(x => x.Zustand).HasMaxLength(64);
        entity.Property(x => x.Ereignis).HasMaxLength(512);
        entity.Property(x => x.Aktor).HasMaxLength(256);
        entity.HasIndex(x => x.JobId);
    }
}
