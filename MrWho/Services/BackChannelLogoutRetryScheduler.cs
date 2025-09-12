using System.Collections.Concurrent;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace MrWho.Services;

public record BackChannelLogoutRetryWork(string ClientId, string Subject, string SessionId, int Attempt = 1)
{
    public DateTime ScheduledAtUtc { get; init; } = DateTime.UtcNow;
}

public interface IBackChannelLogoutRetryScheduler
{
    void ScheduleRetry(BackChannelLogoutRetryWork work);
}

public class BackChannelLogoutRetryScheduler : BackgroundService, IBackChannelLogoutRetryScheduler
{
    private readonly ILogger<BackChannelLogoutRetryScheduler> _logger;
    private readonly IServiceProvider _sp;
    private readonly ConcurrentQueue<BackChannelLogoutRetryWork> _queue = new();
    private readonly List<BackChannelLogoutRetryWork> _deferred = new();
    private readonly int _maxAttempts = 4; // initial + 3 retries
    private static readonly int[] BackoffSeconds = new[] { 60, 300, 900 }; // 1m,5m,15m

    public BackChannelLogoutRetryScheduler(ILogger<BackChannelLogoutRetryScheduler> logger, IServiceProvider sp)
    { _logger = logger; _sp = sp; }

    public void ScheduleRetry(BackChannelLogoutRetryWork work)
    {
        if (work.Attempt >= _maxAttempts)
        {
            _logger.LogWarning("Max attempts reached for client {ClientId}, subject {Sub}", work.ClientId, work.Subject);
            // terminal audit
            try
            {
                using var scope = _sp.CreateScope();
                var audit = scope.ServiceProvider.GetService<ISecurityAuditWriter>();
                audit?.WriteAsync("logout", "backchannel.retry.exhausted", new { work.ClientId, work.Subject, work.SessionId }, "error", actorClientId: work.ClientId);
            }
            catch { }
            return;
        }
        var delayIdx = work.Attempt - 1;
        var delay = delayIdx < BackoffSeconds.Length ? BackoffSeconds[delayIdx] : BackoffSeconds.Last();
        var scheduled = work with { Attempt = work.Attempt + 1, ScheduledAtUtc = DateTime.UtcNow.AddSeconds(delay) };
        lock (_deferred) { _deferred.Add(scheduled); }
        _logger.LogInformation("Scheduled back-channel logout retry attempt {Attempt} for client {ClientId} in {Delay}s", scheduled.Attempt, work.ClientId, delay);
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                // Promote due deferred items
                var now = DateTime.UtcNow;
                List<BackChannelLogoutRetryWork> due = new();
                lock (_deferred)
                {
                    for (int i = _deferred.Count - 1; i >= 0; i--)
                    {
                        if (_deferred[i].ScheduledAtUtc <= now)
                        {
                            due.Add(_deferred[i]);
                            _deferred.RemoveAt(i);
                        }
                    }
                }
                foreach (var d in due) _queue.Enqueue(d);

                if (_queue.TryDequeue(out var work))
                {
                    using var scope = _sp.CreateScope();
                    var service = scope.ServiceProvider.GetRequiredService<IBackChannelLogoutService>();
                    _logger.LogInformation("Retrying back-channel logout attempt {Attempt} for client {ClientId}", work.Attempt, work.ClientId);
                    try
                    {
                        await service.NotifyClientLogoutAsync(work.ClientId, work.Subject, work.SessionId);
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, "Retry attempt {Attempt} failed for client {ClientId}", work.Attempt, work.ClientId);
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Retry scheduler loop error");
            }
            await Task.Delay(2000, stoppingToken); // poll interval
        }
    }
}
