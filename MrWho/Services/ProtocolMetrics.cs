using System.Collections.Concurrent;

namespace MrWho.Services;

public interface IProtocolMetrics
{
    void IncrementJarRequest(string outcome, string alg);
    void IncrementJarReplayBlocked();
    void IncrementJarmResponse(string outcome); // outcome: success|error|failure
    ProtocolMetricsSnapshot GetSnapshot();
}

public sealed record ProtocolMetricsSnapshot(
    IReadOnlyDictionary<string, int> JarRequests,
    int JarReplayBlocked,
    IReadOnlyDictionary<string, int> JarmResponses);

internal sealed class InMemoryProtocolMetrics : IProtocolMetrics
{
    private readonly ConcurrentDictionary<string, int> _jar = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, int> _jarm = new(StringComparer.OrdinalIgnoreCase);
    private int _jarReplayBlocked;

    public void IncrementJarRequest(string outcome, string alg)
    {
        var safeAlg = string.IsNullOrWhiteSpace(alg) ? "unknown" : alg.ToUpperInvariant();
        var safeOutcome = string.IsNullOrWhiteSpace(outcome) ? "unknown" : outcome.ToLowerInvariant();
        var key = $"{safeAlg}:{safeOutcome}";
        _jar.AddOrUpdate(key, 1, (_, v) => v + 1);
    }

    public void IncrementJarReplayBlocked()
    {
        Interlocked.Increment(ref _jarReplayBlocked);
    }

    public void IncrementJarmResponse(string outcome)
    {
        var safeOutcome = string.IsNullOrWhiteSpace(outcome) ? "unknown" : outcome.ToLowerInvariant();
        _jarm.AddOrUpdate(safeOutcome, 1, (_, v) => v + 1);
    }

    public ProtocolMetricsSnapshot GetSnapshot() => new(
        _jar.ToDictionary(kvp => kvp.Key, kvp => kvp.Value, StringComparer.OrdinalIgnoreCase),
        Volatile.Read(ref _jarReplayBlocked),
        _jarm.ToDictionary(kvp => kvp.Key, kvp => kvp.Value, StringComparer.OrdinalIgnoreCase));
}
