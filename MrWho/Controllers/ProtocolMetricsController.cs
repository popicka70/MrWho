using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using MrWho.Services;
using MrWho.Shared;

namespace MrWho.Controllers;

[ApiController]
[Route("api/monitoring/protocol-metrics")]
[Authorize(Policy = AuthorizationPolicies.MetricsRead)]
public class ProtocolMetricsController : ControllerBase
{
    private readonly IProtocolMetrics _metrics;
    private readonly ILogger<ProtocolMetricsController> _logger;

    public ProtocolMetricsController(IProtocolMetrics metrics, ILogger<ProtocolMetricsController> logger)
    {
        _metrics = metrics;
        _logger = logger;
    }

    /// <summary>
    /// Returns current in-memory protocol metrics snapshot (JAR/JARM/PAR subset).
    /// </summary>
    [HttpGet]
    public ActionResult<object> Get()
    {
        try
        {
            var snap = _metrics.GetSnapshot();
            Response.Headers.CacheControl = "no-store";
            Response.Headers.Pragma = "no-cache";
            return Ok(new
            {
                captured_at_utc = snap.CapturedAtUtc,
                jar_requests = snap.JarRequests,
                jar_replay_blocked = snap.JarReplayBlocked,
                jar_secret_fallbacks = snap.JarSecretFallbacks,
                jarm_responses = snap.JarmResponses,
                par_pushes = snap.ParPushes,
                par_resolutions = snap.ParResolutions,
                validation_events = snap.ValidationEvents
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to get protocol metrics snapshot");
            return StatusCode(500, new { error = "metrics_error", error_description = ex.Message });
        }
    }

    /// <summary>
    /// Resets the in-memory protocol metrics counters.
    /// </summary>
    [HttpPost("reset")]
    public IActionResult Reset()
    {
        try
        {
            _metrics.Reset();
            return NoContent();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to reset protocol metrics");
            return StatusCode(500, new { error = "metrics_error", error_description = ex.Message });
        }
    }
}
