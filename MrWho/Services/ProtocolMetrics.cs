using System.Collections.Concurrent;

namespace MrWho.Services;

public interface IProtocolMetrics
{
    void IncrementJarRequest(string outcome, string alg);
    void IncrementJarmResponse(string outcome);
    ProtocolMetricsSnapshot GetSnapshot();
}

public sealed record ProtocolMetricsSnapshot(
    IReadOnlyDictionary<string,int> JarRequests,
    IReadOnlyDictionary<string,int> JarmResponses);

internal sealed class InMemoryProtocolMetrics : IProtocolMetrics
{
    private readonly ConcurrentDictionary<string,int> _jar = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string,int> _jarm = new(StringComparer.OrdinalIgnoreCase);

    public void IncrementJarRequest(string outcome, string alg)
    {
        var key = $"{alg}:{outcome}";
        _jar.AddOrUpdate(key, 1, (_, v) => v + 1);
    }

    public void IncrementJarmResponse(string outcome)
    {
        _jarm.AddOrUpdate(outcome, 1, (_, v) => v + 1);
    }

    public ProtocolMetricsSnapshot GetSnapshot() => new(
        _jar.ToDictionary(kvp => kvp.Key, kvp => kvp.Value, StringComparer.OrdinalIgnoreCase),
        _jarm.ToDictionary(kvp => kvp.Key, kvp => kvp.Value, StringComparer.OrdinalIgnoreCase));
}
