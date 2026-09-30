using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace OfficeSelfSigningPortal.WorkerService.Retention;

/// <summary>
/// Hosted Service des Retention-Jobs (Ticket 11, REQ-19): führt den
/// <see cref="RetentionExecutor"/> beim Start aus und danach im konfigurierten
/// Intervall. Der Executor läuft pro Lauf in einem eigenen Scope (DbContexts
/// sind scoped); Ausfälle einzelner Läufe werden geloggt und den nächsten Lauf
/// nicht blockieren. Das Intervall läuft über den <see cref="TimeProvider"/>
/// (konsistent mit der fälschbaren Uhr des Executors).
/// </summary>
public sealed class RetentionJob(
    IServiceScopeFactory scopeFactory,
    TimeProvider timeProvider,
    IOptions<RetentionOptions> options,
    ILogger<RetentionJob> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await using var scope = scopeFactory.CreateAsyncScope();
                var executor = scope.ServiceProvider.GetRequiredService<RetentionExecutor>();
                await executor.ExecuteAsync(stoppingToken);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                logger.LogError(ex, "Retention-Lauf fehlgeschlagen — nächster Lauf zum konfigurierten Intervall");
            }

            try
            {
                await Task.Delay(options.Value.ExecutionInterval, timeProvider, stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
        }
    }
}
