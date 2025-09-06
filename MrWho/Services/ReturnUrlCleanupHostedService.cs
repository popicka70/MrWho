using Microsoft.Extensions.Hosting;

namespace MrWho.Services;

/// <summary>
/// Background task that periodically cleans expired ReturnUrlEntries from the database.
/// </summary>
public class ReturnUrlCleanupHostedService : BackgroundService
{
    private readonly ILogger<ReturnUrlCleanupHostedService> _logger;
    private readonly IServiceProvider _services;
    private readonly TimeSpan _interval = TimeSpan.FromHours(1);

    public ReturnUrlCleanupHostedService(ILogger<ReturnUrlCleanupHostedService> logger, IServiceProvider services)
    {
        _logger = logger;
        _services = services;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("ReturnUrl cleanup hosted service started");
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                using var scope = _services.CreateScope();
                var store = scope.ServiceProvider.GetRequiredService<IReturnUrlStore>();
                var removed = await store.CleanupExpiredAsync(stoppingToken);
                if (removed > 0)
                {
                    _logger.LogInformation("ReturnUrl cleanup removed {Count} expired entries", removed);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during ReturnUrl cleanup");
            }

            try
            {
                await Task.Delay(_interval, stoppingToken);
            }
            catch (TaskCanceledException) { }
        }
    }
}
