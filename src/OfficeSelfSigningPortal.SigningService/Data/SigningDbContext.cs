using Microsoft.EntityFrameworkCore;

namespace OfficeSelfSigningPortal.SigningService.Data;

/// <summary>
/// DbContext des SigningService (fachlicher Kontext Signierung). Das
/// Vorfalls-Protokoll des Guards (AK-39) wurde mit Ticket 06 in den
/// konsolidierten Audit-Trail (Ossp.Audit, portal-DB) überführt; der Kontext
/// bleibt als Migrationseigner der signing-DB erhalten (Signier-Pipeline, Ticket 08).
/// </summary>
public class SigningDbContext(DbContextOptions<SigningDbContext> options) : DbContext(options)
{
    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
    }
}
