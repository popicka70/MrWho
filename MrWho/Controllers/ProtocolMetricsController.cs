using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using MrWho.Services;
using MrWho.Shared;
using MrWho.Shared.Authentication;

namespace MrWho.Controllers;

[ApiController]
[Route("api/monitoring/protocol-metrics")]
[Authorize(Policy = AuthorizationPolicies.AdminClientApi)]
public class ProtocolMetricsController : ControllerBase
{
    private readonly IProtocolMetrics _metrics;
    public ProtocolMetricsController(IProtocolMetrics metrics) => _metrics = metrics;

    /// <summary>
    /// Returns current in-memory protocol metrics snapshot (JAR/JARM/PAR subset).
    /// </summary>
    [HttpGet]
    public ActionResult<object> Get()
    {
        var snap = _metrics.GetSnapshot();
        return Ok(new
        {
            jar_requests = snap.JarRequests,
            jar_replay_blocked = snap.JarReplayBlocked,
            jarm_responses = snap.JarmResponses
        });
    }
}
