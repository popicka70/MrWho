using System.Collections.Concurrent;

namespace MrWho.Services;

public interface IProtocolMetrics
{
    // JAR
    void IncrementJarRequest(string outcome, string alg); // outcome: success|reject|replay|error
    void IncrementJarReplayBlocked();
    void IncrementJarSecretFallback(); // NEW: count HS secret fallback usages
    // JARM
    void IncrementJarmResponse(string outcome); // outcome: success|error|failure
    // PAR
    void IncrementParPush(string outcome); // outcome: created|reused|error
    void IncrementParResolve(string outcome); // outcome: resolved|missing|expired|consumed|error
    // Limits / conflicts
    void IncrementValidationEvent(string category, string outcome); // category: conflict|limit  outcome: reject|skip|error
    ProtocolMetricsSnapshot GetSnapshot();
    void Reset();
}

public sealed record ProtocolMetricsSnapshot(
    IReadOnlyDictionary<string, int> JarRequests,
    int JarReplayBlocked,
    int JarSecretFallbacks,
    IReadOnlyDictionary<string, int> JarmResponses,
    IReadOnlyDictionary<string, int> ParPushes,
    IReadOnlyDictionary<string, int> ParResolutions,
    IReadOnlyDictionary<string, int> ValidationEvents,
    DateTimeOffset CapturedAtUtc);

internal sealed class InMemoryProtocolMetrics : IProtocolMetrics
{
    private readonly ConcurrentDictionary<string, int> _jar = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, int> _jarm = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, int> _parPush = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, int> _parResolve = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, int> _validation = new(StringComparer.OrdinalIgnoreCase);
    private int _jarReplayBlocked;
    private int _jarSecretFallbacks;

    public void IncrementJarRequest(string outcome, string alg)
    {
        var safeAlg = string.IsNullOrWhiteSpace(alg) ? "unknown" : alg.ToUpperInvariant();
        var safeOutcome = string.IsNullOrWhiteSpace(outcome) ? "unknown" : outcome.ToLowerInvariant();
        var key = $"{safeAlg}:{safeOutcome}";
        _jar.AddOrUpdate(key, 1, (_, v) => v + 1);
    }

    public void IncrementJarReplayBlocked() => Interlocked.Increment(ref _jarReplayBlocked);

    public void IncrementJarSecretFallback() => Interlocked.Increment(ref _jarSecretFallbacks);

    public void IncrementJarmResponse(string outcome)
    {
        var safeOutcome = string.IsNullOrWhiteSpace(outcome) ? "unknown" : outcome.ToLowerInvariant();
        _jarm.AddOrUpdate(safeOutcome, 1, (_, v) => v + 1);
    }

    public void IncrementParPush(string outcome)
    {
        var safe = string.IsNullOrWhiteSpace(outcome) ? "unknown" : outcome.ToLowerInvariant();
        _parPush.AddOrUpdate(safe, 1, (_, v) => v + 1);
    }

    public void IncrementParResolve(string outcome)
    {
        var safe = string.IsNullOrWhiteSpace(outcome) ? "unknown" : outcome.ToLowerInvariant();
        _parResolve.AddOrUpdate(safe, 1, (_, v) => v + 1);
    }

    public void IncrementValidationEvent(string category, string outcome)
    {
        var c = string.IsNullOrWhiteSpace(category) ? "unknown" : category.ToLowerInvariant();
        var o = string.IsNullOrWhiteSpace(outcome) ? "unknown" : outcome.ToLowerInvariant();
        var key = $"{c}:{o}";
        _validation.AddOrUpdate(key, 1, (_, v) => v + 1);
    }

    public ProtocolMetricsSnapshot GetSnapshot() => new(
        _jar.ToDictionary(kvp => kvp.Key, kvp => kvp.Value, StringComparer.OrdinalIgnoreCase),
        Volatile.Read(ref _jarReplayBlocked),
        Volatile.Read(ref _jarSecretFallbacks),
        _jarm.ToDictionary(kvp => kvp.Key, kvp => kvp.Value, StringComparer.OrdinalIgnoreCase),
        _parPush.ToDictionary(kvp => kvp.Key, kvp => kvp.Value, StringComparer.OrdinalIgnoreCase),
        _parResolve.ToDictionary(kvp => kvp.Key, kvp => kvp.Value, StringComparer.OrdinalIgnoreCase),
        _validation.ToDictionary(kvp => kvp.Key, kvp => kvp.Value, StringComparer.OrdinalIgnoreCase),
        DateTimeOffset.UtcNow);

    public void Reset()
    {
        _jar.Clear();
        _jarm.Clear();
        _parPush.Clear();
        _parResolve.Clear();
        _validation.Clear();
        Interlocked.Exchange(ref _jarReplayBlocked, 0);
        Interlocked.Exchange(ref _jarSecretFallbacks, 0);
    }
}
