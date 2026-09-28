namespace OfficeSelfSigningPortal.SigningService;

public class Worker(ILogger<Worker> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            logger.LogInformation("SigningService läuft");
            await Task.Delay(TimeSpan.FromMinutes(1), stoppingToken);
        }
    }
}
