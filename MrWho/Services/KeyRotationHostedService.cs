using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using MrWho.Options;

namespace MrWho.Services;

public class KeyRotationHostedService : BackgroundService
{
    private readonly ILogger<KeyRotationHostedService> _logger;
    private readonly IKeyManagementService _kms;
    private readonly IOptions<KeyManagementOptions> _options;

    public KeyRotationHostedService(ILogger<KeyRotationHostedService> logger, IKeyManagementService kms, IOptions<KeyManagementOptions> options)
    {
        _logger = logger;
        _kms = kms;
        _options = options;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        // Initial ensure
        await SafeEnsureAsync(stoppingToken);

        // Periodic check: run every 6 hours (cheap DB calls)
        var delay = TimeSpan.FromHours(6);
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(delay, stoppingToken);
                await SafeEnsureAsync(stoppingToken);
            }
            catch (TaskCanceledException) { }
        }
    }

    private async Task SafeEnsureAsync(CancellationToken ct)
    {
        try
        {
            if (!_options.Value.Enabled)
            {
                return;
            }

            await _kms.EnsureInitializedAsync(ct);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Key rotation ensure failed");
        }
    }
}
