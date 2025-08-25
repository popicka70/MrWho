using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace MrWho.Services;

/// <summary>
/// No-op implementation now that dynamic per-client cookie schemes were removed.
/// Keeps startup initialization code intact without failing DI.
/// </summary>
public sealed class DynamicClientCookieRegistrar : IDynamicClientCookieRegistrar
{
    private readonly ILogger<DynamicClientCookieRegistrar> _logger;
    private int _initialized;

    public DynamicClientCookieRegistrar(ILogger<DynamicClientCookieRegistrar> logger)
    {
        _logger = logger;
    }

    public Task RegisterAllAsync(CancellationToken cancellationToken = default)
    {
        if (Interlocked.Exchange(ref _initialized, 1) == 0)
        {
            _logger.LogInformation("DynamicClientCookieRegistrar no-op registration executed (single-cookie mode)");
        }
        return Task.CompletedTask;
    }
}
