using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using MrWho.Services;
using QRCoder;
using MrWho.Models; // add
using MrWho.Shared; // ensure shared enums

namespace MrWho.Controllers;

[Route("qr")] 
public class QrController : Controller
{
    private readonly IPersistentQrLoginService _qr;
    private readonly ILogger<QrController> _logger;

    public QrController(IPersistentQrLoginService qr, ILogger<QrController> logger)
    {
        _qr = qr; _logger = logger;
    }

    // Start a new persistent QR login session (anonymous; approval requires auth)
    [HttpGet("start")]
    [AllowAnonymous]
    public async Task<IActionResult> Start([FromQuery] string? clientId = null, [FromQuery] string? returnUrl = null)
    {
        var dto = await _qr.CreateAsync(clientId, returnUrl, deviceId: null, ttl: TimeSpan.FromMinutes(5), initiatorIp: HttpContext.Connection.RemoteIpAddress?.ToString());
        ViewData["Token"] = dto.Token;
        ViewData["Csrf"] = dto.Csrf;
        ViewData["ClientId"] = clientId;
        ViewData["ReturnUrl"] = returnUrl;
        ViewData["ExpiresAt"] = dto.ExpiresAt;
        return View("Start");
    }

    // Simple status endpoint used by JS poller (no auth needed)
    [HttpGet("status/{token}")]
    [AllowAnonymous]
    public async Task<IActionResult> Status(string token)
    {
        var dto = await _qr.GetAsync(token);
        if (dto == null)
            return NotFound(new { status = "expired" });
        return Json(new { status = dto.Status.ToString(), approved = dto.Status == MrWho.Shared.QrSessionStatus.Approved, completed = dto.Status == MrWho.Shared.QrSessionStatus.Completed });
    }

    // Completion endpoint: invoked by initiating browser once approved
    [HttpPost("complete")]
    [AllowAnonymous]
    public async Task<IActionResult> Complete([FromForm] string token, [FromForm] string csrf)
    {
        var dto = await _qr.GetAsync(token);
        if (dto == null) return NotFound();
        if (dto.Status != MrWho.Shared.QrSessionStatus.Approved) return BadRequest(new { error = "not_approved" });
        var ok = await _qr.CompleteAsync(token, csrf);
        if (!ok) return BadRequest(new { error = "complete_failed" });
        // Do NOT sign user in here because approval-side signed user context (on device). Full SSO still requires normal OIDC authorize redirect
        return Ok(new { status = "completed" });
    }

    // Approval UI (opened on authenticated device after scanning code) - shows data and allows JS call to API approve endpoint
    [HttpGet("approve")]
    [Authorize]
    public IActionResult Approve([FromQuery] string token, [FromQuery] string csrf)
    {
        ViewData["Token"] = token;
        ViewData["Csrf"] = csrf;
        return View("Approve");
    }

    [HttpGet("code/{token}.png")]
    [AllowAnonymous]
    public IActionResult Code(string token, [FromQuery] string csrf)
    {
        // Encode approval deep link containing token & csrf so approving device has secret needed
        var approveUrl = Url.Action("Approve", "Qr", new { token, csrf }, Request.Scheme, Request.Host.ToString());
        using var generator = new QRCodeGenerator();
        var data = generator.CreateQrCode(approveUrl, QRCodeGenerator.ECCLevel.Q);
        var png = new PngByteQRCode(data).GetGraphic(8);
        return File(png, "image/png");
    }
}
