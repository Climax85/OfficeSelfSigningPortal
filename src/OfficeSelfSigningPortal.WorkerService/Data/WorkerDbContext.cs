using Microsoft.EntityFrameworkCore;

namespace OfficeSelfSigningPortal.WorkerService.Data;

/// <summary>
/// DbContext des WorkerService (fachlicher Kontext Analyse/Saga).
/// Entitäten folgen in den Folgetickets; die Migrations-Pipeline steht bereits.
/// </summary>
public class WorkerDbContext(DbContextOptions<WorkerDbContext> options) : DbContext(options);
