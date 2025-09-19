using System.Diagnostics.Metrics;

namespace MrWho.Services;

/// <summary>
/// Central PAR/JAR/JARM metrics (Phase 2 PJ51 initial PAR counters + PJ40/PJ41 additions).
/// Exposed via System.Diagnostics.Metrics so exporters (OpenTelemetry, etc.) can pick them up.
/// </summary>
internal static class ParMetrics
{
    private static readonly Meter _meter = new("MrWho.Oidc", "1.0.0");

    // PAR counters
    private static readonly Counter<long> _parRequests = _meter.CreateCounter<long>("par_requests_total", description: "Total PAR push attempts (new+reuse)");
    private static readonly Counter<long> _parReuseHits = _meter.CreateCounter<long>("par_reuse_hits_total", description: "PAR push requests that reused an existing entry");
    private static readonly Counter<long> _parResolutions = _meter.CreateCounter<long>("par_resolutions_total", description: "Successful request_uri resolutions at authorize endpoint");
    private static readonly Counter<long> _parResolutionMiss = _meter.CreateCounter<long>("par_resolution_miss_total", description: "Failed/expired request_uri resolutions");
    private static readonly Counter<long> _parConsumed = _meter.CreateCounter<long>("par_consumed_total", description: "Single-use PAR entries consumed");
    private static readonly Counter<long> _parReplayRejected = _meter.CreateCounter<long>("par_replay_rejected_total", description: "Rejected duplicate use of single-use PAR entry");

    // PJ40 conflict detection
    private static readonly Counter<long> _requestConflicts = _meter.CreateCounter<long>("par_jar_conflicts_total", description: "Query vs request object/PAR parameter conflicts detected");

    // PJ41 limit violations
    private static readonly Counter<long> _requestLimitViolations = _meter.CreateCounter<long>("par_jar_limit_violations_total", description: "Request parameter limit violations");

    public static void RecordParPush(string clientId, bool reused)
    {
        _parRequests.Add(1, KeyValuePair.Create<string, object?>("client_id", clientId), KeyValuePair.Create<string, object?>("reused", reused));
        if (reused)
            _parReuseHits.Add(1, KeyValuePair.Create<string, object?>("client_id", clientId));
    }

    public static void RecordResolution(bool success)
    {
        if (success) _parResolutions.Add(1);
        else _parResolutionMiss.Add(1);
    }

    public static void RecordConsumed() => _parConsumed.Add(1);
    public static void RecordReplayRejected() => _parReplayRejected.Add(1);

    public static void RecordConflict(string parameterName)
        => _requestConflicts.Add(1, KeyValuePair.Create<string, object?>("parameter", parameterName));

    public static void RecordLimitViolation(string rule)
        => _requestLimitViolations.Add(1, KeyValuePair.Create<string, object?>("rule", rule));
}
