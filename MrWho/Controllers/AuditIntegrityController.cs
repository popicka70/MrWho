using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using MrWho.Services;

namespace MrWho.Controllers;

[ApiController]
[Route("health/audit-integrity")] // per backlog: /health/audit-integrity
[Authorize] // tighten later with specific policy if needed
public class AuditIntegrityController : ControllerBase
{
    private readonly IAuditIntegrityVerificationService _verifier;

    public AuditIntegrityController(IAuditIntegrityVerificationService verifier)
    { _verifier = verifier; }

    [HttpGet]
    public async Task<IActionResult> Get([FromQuery] int max = 0, CancellationToken ct = default)
    {
        var head = await _verifier.GetHeadAsync(ct);
        var result = await _verifier.VerifyAsync(max, ct);
        return Ok(new
        {
            headId = head?.Id,
            headTimestampUtc = head?.TimestampUtc,
            result.TotalScanned,
            result.Breaks,
            result.FirstBrokenId,
            result.LastId,
            elapsedMs = (int)result.Elapsed.TotalMilliseconds,
            status = result.Breaks == 0 ? "ok" : "broken"
        });
    }
}
