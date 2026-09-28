using Microsoft.EntityFrameworkCore;

namespace OfficeSelfSigningPortal.WebUI.Data;

/// <summary>
/// DbContext der WebUI (fachlicher Kontext Portal: Uploads, Reviews, Audit).
/// Entitäten folgen in den Folgetickets; die Migrations-Pipeline steht bereits.
/// </summary>
public class PortalDbContext(DbContextOptions<PortalDbContext> options) : DbContext(options);
