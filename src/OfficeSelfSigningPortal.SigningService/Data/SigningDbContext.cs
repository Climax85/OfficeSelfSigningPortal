using Microsoft.EntityFrameworkCore;
using OfficeSelfSigningPortal.SigningService.Messaging;

namespace OfficeSelfSigningPortal.SigningService.Data;

/// <summary>
/// DbContext des SigningService (fachlicher Kontext Signierung). Hält die
/// Vorfalls-Protokoll-Tabelle des Guards (AK-39); Ticket 06 konsolidiert sie in
/// den hash-verketteten Audit-Trail.
/// </summary>
public class SigningDbContext(DbContextOptions<SigningDbContext> options) : DbContext(options)
{
    public DbSet<SigningIncident> SigningIncidents => Set<SigningIncident>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<SigningIncident>(entity =>
        {
            entity.ToTable("signing_incidents");
            entity.HasKey(x => x.Id);
            entity.Property(x => x.Reason).HasMaxLength(512);
            entity.HasIndex(x => x.JobId);
        });
    }
}
