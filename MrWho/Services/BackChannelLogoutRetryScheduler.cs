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
    void ReportAttemptOutcome(string clientId, string subject, string sessionId, int attempt, bool success, string? status, string? error);
    void ReportExhausted(string clientId, string subject, string sessionId, int attempts);
}

public class BackChannelLogoutRetryScheduler : BackgroundService, IBackChannelLogoutRetryScheduler
{
    private readonly ILogger<BackChannelLogoutRetryScheduler> _logger;
    private readonly IServiceProvider _sp;
    private readonly ConcurrentQueue<BackChannelLogoutRetryWork> _queue = new();
    private readonly List<BackChannelLogoutRetryWork> _deferred = new();
    private readonly int _maxAttempts = 4; // attempt numbers: 1 initial + 3 retries
    private static readonly int[] BackoffSeconds = new[] { 60, 300, 900 }; // 1m,5m,15m

    // Track attempt history for aggregate result (key = client|session)
    private readonly ConcurrentDictionary<string, List<AttemptRecord>> _attempts = new();
    private record AttemptRecord(int Attempt, bool Success, string? Status, string? Error, DateTime Utc);

    public BackChannelLogoutRetryScheduler(ILogger<BackChannelLogoutRetryScheduler> logger, IServiceProvider sp)
    { _logger = logger; _sp = sp; }

    private static string Key(string clientId, string sessionId) => clientId + "|" + sessionId;

    public void ScheduleRetry(BackChannelLogoutRetryWork work)
    {
        if (work.Attempt >= _maxAttempts)
        {
            _logger.LogWarning("Max attempts reached for client {ClientId}, session {SessionId}", work.ClientId, work.SessionId);
            ReportExhausted(work.ClientId, work.Subject, work.SessionId, work.Attempt);
            return;
        }
        var delayIdx = work.Attempt - 1; // attempt 1 failed -> index 0
        var delay = delayIdx < BackoffSeconds.Length ? BackoffSeconds[delayIdx] : BackoffSeconds.Last();
        var scheduled = work with { Attempt = work.Attempt + 1, ScheduledAtUtc = DateTime.UtcNow.AddSeconds(delay) };
        lock (_deferred) { _deferred.Add(scheduled); }
        _logger.LogInformation("Scheduled back-channel logout retry attempt {Attempt} for client {ClientId} in {Delay}s (session={SessionId})", scheduled.Attempt, work.ClientId, delay, work.SessionId);
        try
        {
            using var scope = _sp.CreateScope();
            var audit = scope.ServiceProvider.GetService<ISecurityAuditWriter>();
            audit?.WriteAsync("logout", "backchannel.retry.scheduled", new { work.ClientId, work.SessionId, nextAttempt = scheduled.Attempt, delaySeconds = delay }, "info", actorClientId: work.ClientId);
        }
        catch { }
    }

    public void ReportAttemptOutcome(string clientId, string subject, string sessionId, int attempt, bool success, string? status, string? error)
    {
        var list = _attempts.GetOrAdd(Key(clientId, sessionId), _ => new List<AttemptRecord>());
        lock (list) list.Add(new AttemptRecord(attempt, success, status, error, DateTime.UtcNow));
        try
        {
            using var scope = _sp.CreateScope();
            var audit = scope.ServiceProvider.GetService<ISecurityAuditWriter>();
            audit?.WriteAsync("logout", success ? "backchannel.retry.attempt.success" : "backchannel.retry.attempt.failure", new { clientId, sessionId, attempt, status, error }, success ? "info" : "warn", actorClientId: clientId);
        }
        catch { }

        if (success || attempt >= _maxAttempts)
        {
            // Emit aggregate summary
            EmitAggregate(clientId, sessionId, subject);
        }
    }

    public void ReportExhausted(string clientId, string subject, string sessionId, int attempts)
    {
        try
        {
            using var scope = _sp.CreateScope();
            var audit = scope.ServiceProvider.GetService<ISecurityAuditWriter>();
            audit?.WriteAsync("logout", "backchannel.retry.exhausted", new { clientId, sessionId, attempts }, "error", actorClientId: clientId);
        }
        catch { }
        EmitAggregate(clientId, sessionId, subject, exhausted: true);
    }

    private void EmitAggregate(string clientId, string sessionId, string subject, bool exhausted = false)
    {
        var key = Key(clientId, sessionId);
        if (!_attempts.TryGetValue(key, out var list)) return;
        List<AttemptRecord> snapshot;
        lock (list) snapshot = list.ToList();
        var success = snapshot.Any(a => a.Success);
        try
        {
            using var scope = _sp.CreateScope();
            var audit = scope.ServiceProvider.GetService<ISecurityAuditWriter>();
            audit?.WriteAsync("logout", "backchannel.retry.result", new
            {
                clientId,
                sessionId,
                subject,
                attemptsTried = snapshot.Count,
                success,
                exhausted = exhausted || (!success && snapshot.Count >= _maxAttempts),
                failures = snapshot.Where(a => !a.Success).Select(a => new { a.Attempt, a.Status, a.Error })
            }, success ? "info" : "error", actorClientId: clientId);
        }
        catch { }
        // Remove history after aggregate to free memory
        _attempts.TryRemove(key, out _);
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
                    _logger.LogInformation("Retrying back-channel logout attempt {Attempt} for client {ClientId} (session={SessionId})", work.Attempt, work.ClientId, work.SessionId);
                    try
                    {
                        // Invoke dispatch; the service will record attempt outcome #1 only. Scheduler must record its own attempt outcome (attempt>=2)
                        await service.NotifyClientLogoutAsync(work.ClientId, work.Subject, work.SessionId, null /* token */);
                        // For retry attempts (>=2), we optimistically mark success; on real failure, the service already scheduled further retry and reported outcome.
                        ReportAttemptOutcome(work.ClientId, work.Subject, work.SessionId, work.Attempt, success: true, status: "ok", error: null);
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, "Retry attempt {Attempt} failed throwing exception for client {ClientId}", work.Attempt, work.ClientId);
                        ReportAttemptOutcome(work.ClientId, work.Subject, work.SessionId, work.Attempt, success: false, status: null, error: ex.Message);
                        // Schedule next manually if not already scheduled
                        ScheduleRetry(work);
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Retry scheduler loop error");
            }
            await Task.Delay(2000, stoppingToken);
        }
    }
}
