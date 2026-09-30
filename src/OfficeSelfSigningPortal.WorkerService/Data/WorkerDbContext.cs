using MassTransit;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using OfficeSelfSigningPortal.WorkerService.Saga;

namespace OfficeSelfSigningPortal.WorkerService.Data;

/// <summary>
/// DbContext des WorkerService (fachlicher Kontext Analyse/Saga). Hält die
/// Saga-Instanz und die MassTransit-Outbox-Tabellen (REQ-11, TM-06). Der
/// Übergangs-Audit wurde mit Ticket 06 in den konsolidierten Audit-Trail
/// (Ossp.Audit, portal-DB) überführt.
/// </summary>
public class WorkerDbContext(DbContextOptions<WorkerDbContext> options) : DbContext(options)
{
    public DbSet<AnalysisSagaState> SagaStates => Set<AnalysisSagaState>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<AnalysisSagaState>(ConfigureAnalysisSagaState);
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
        entity.Property(x => x.SubmitterEmail).HasMaxLength(256);
        entity.Property(x => x.OriginalFileName).HasMaxLength(512);
        entity.Property(x => x.ContentType).HasMaxLength(16);
        entity.Property(x => x.ContentSha256).HasMaxLength(64);
        entity.HasIndex(x => x.ReceivedAt);
        entity.Property(x => x.SignedArtifactId); // Nullable — gesetzt mit SignMacroCompleted (Ticket 08)
    }
}
