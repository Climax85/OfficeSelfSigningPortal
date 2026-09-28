using Microsoft.EntityFrameworkCore;

namespace OfficeSelfSigningPortal.SigningService.Data;

/// <summary>
/// DbContext des SigningService (fachlicher Kontext Signierung).
/// Entitäten folgen in den Folgetickets; die Migrations-Pipeline steht bereits.
/// </summary>
public class SigningDbContext(DbContextOptions<SigningDbContext> options) : DbContext(options);
