using Microsoft.EntityFrameworkCore;

namespace OfficeSelfSigningPortal.WebUI.Data;

public class PortalDbContext(DbContextOptions<PortalDbContext> options) : DbContext(options)
{
    public DbSet<AnalysisJob> AnalysisJobs => Set<AnalysisJob>();

    public DbSet<Artifact> Artifacts => Set<Artifact>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<AnalysisJob>(entity =>
        {
            entity.ToTable("analysis_jobs");
            entity.HasKey(j => j.JobId);
            entity.Property(j => j.Status)
                .HasConversion<string>(); // verbindliche Zustandsbezeichner (Anhang B)
            entity.HasOne(j => j.Artifact)
                .WithOne(a => a.Job)
                .HasForeignKey<AnalysisJob>(j => j.ArtifactId)
                .OnDelete(DeleteBehavior.Cascade);
        });

        modelBuilder.Entity<Artifact>(entity =>
        {
            entity.ToTable("artifacts");
            entity.HasKey(a => a.ArtifactId);
        });
    }
}
