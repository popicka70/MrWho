using Microsoft.Extensions.Hosting;

namespace MrWho.Services;

public class TokenStatisticsSnapshotHostedService : BackgroundService
{
    private readonly IServiceProvider _services;
    private readonly ILogger<TokenStatisticsSnapshotHostedService> _logger;

    public TokenStatisticsSnapshotHostedService(IServiceProvider services, ILogger<TokenStatisticsSnapshotHostedService> logger)
    {
        _services = services;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("TokenStatisticsSnapshotHostedService started");

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                using var scope = _services.CreateScope();
                var svc = scope.ServiceProvider.GetRequiredService<ITokenStatisticsSnapshotService>();

                // Capture hourly snapshot
                await svc.CaptureHourlyAsync(stoppingToken);

                // At UTC midnight, also capture daily and cleanup 180 days by default
                var now = DateTimeOffset.UtcNow;
                if (now.Hour == 0)
                {
                    await svc.CaptureDailyAsync(stoppingToken);
                    await svc.CleanupAsync(TimeSpan.FromDays(180), stoppingToken);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error while capturing token statistics snapshot");
            }

            // Sleep until the next hour boundary to avoid drift
            var nextHour = DateTimeOffset.UtcNow.AddHours(1);
            nextHour = new DateTimeOffset(nextHour.Year, nextHour.Month, nextHour.Day, nextHour.Hour, 0, 0, TimeSpan.Zero);
            var delay = nextHour - DateTimeOffset.UtcNow;
            if (delay < TimeSpan.FromMinutes(1)) {
                delay = TimeSpan.FromMinutes(1);
            }

            await Task.Delay(delay, stoppingToken);
        }

        _logger.LogInformation("TokenStatisticsSnapshotHostedService stopping");
    }
}
