using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using MrWho.Services;
using QRCoder;
using MrWho.Models; // add
using MrWho.Shared; // ensure shared enums
using Microsoft.AspNetCore.Identity;

namespace MrWho.Controllers;

[Route("qr")] 
public class QrController : Controller
{
    private readonly IPersistentQrLoginService _qr;
    private readonly IDynamicCookieService _dynamicCookieService;
    private readonly SignInManager<IdentityUser> _signInManager;
    private readonly UserManager<IdentityUser> _userManager;
    private readonly ILogger<QrController> _logger;

    public QrController(IPersistentQrLoginService qr, IDynamicCookieService dynamicCookieService, SignInManager<IdentityUser> signInManager, UserManager<IdentityUser> userManager, ILogger<QrController> logger)
    {
        _qr = qr; _dynamicCookieService = dynamicCookieService; _signInManager = signInManager; _userManager = userManager; _logger = logger;
    }

    // Start a new persistent QR login session (anonymous; approval requires auth)
    [HttpGet("start")]
    [HttpGet("/qr-login/start")] // legacy alias
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
    [HttpGet("/qr-login/status/{token}")] // legacy alias
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
    [HttpPost("/qr-login/complete")] // legacy alias
    [AllowAnonymous]
    public async Task<IActionResult> Complete([FromForm] string token, [FromForm] string csrf)
    {
        var dto = await _qr.GetAsync(token);
        if (dto == null)
        {
            _logger.LogDebug("[QR] Complete failed - token {Token} not found", token);
            return NotFound();
        }
        if (dto.Status != MrWho.Shared.QrSessionStatus.Approved)
        {
            _logger.LogDebug("[QR] Complete denied - token {Token} status {Status}", token, dto.Status);
            return BadRequest(new { error = "not_approved" });
        }
        if (string.IsNullOrEmpty(dto.UserId))
        {
            _logger.LogWarning("[QR] Complete aborted - approved session {Token} missing user id", token);
            return BadRequest(new { error = "no_user" });
        }
        var user = await _userManager.FindByIdAsync(dto.UserId);
        if (user == null)
        {
            _logger.LogWarning("[QR] Complete aborted - user {UserId} not found", dto.UserId);
            return BadRequest(new { error = "user_not_found" });
        }

        // Sign-in default identity cookie
        await _signInManager.SignInAsync(user, isPersistent: false);
        _logger.LogInformation("[QR] Signed in user {UserName} via QR token {Token}", user.UserName, token);

        // Sign-in client-specific cookie if clientId present
        if (!string.IsNullOrWhiteSpace(dto.ClientId))
        {
            try
            {
                await _dynamicCookieService.SignInWithClientCookieAsync(dto.ClientId, user, rememberMe: false);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "[QR] Failed to issue client cookie for client {ClientId} token {Token}", dto.ClientId, token);
            }
        }

        // Mark session completed (idempotent if already done)
        var completed = await _qr.CompleteAsync(token, csrf);
        if (!completed)
        {
            _logger.LogWarning("[QR] CompleteAsync returned false for token {Token}", token);
        }

        // Redirect logic (Option A)
        if (!string.IsNullOrEmpty(dto.ReturnUrl))
        {
            if (dto.ReturnUrl.Contains("/connect/authorize", StringComparison.OrdinalIgnoreCase))
            {
                _logger.LogDebug("[QR] Redirecting to OIDC authorize: {ReturnUrl}", dto.ReturnUrl);
                return Redirect(dto.ReturnUrl);
            }
            if (Url.IsLocalUrl(dto.ReturnUrl))
            {
                _logger.LogDebug("[QR] Redirecting to local returnUrl: {ReturnUrl}", dto.ReturnUrl);
                return Redirect(dto.ReturnUrl);
            }
        }

        return RedirectToAction("Index", "Home");
    }

    // Approval UI (opened on authenticated device after scanning code) - shows data and allows JS call to API approve endpoint
    [HttpGet("approve")]
    [HttpGet("/qr-login/approve")] // legacy alias
    [Authorize]
    public IActionResult Approve([FromQuery] string token, [FromQuery] string csrf)
    {
        ViewData["Token"] = token;
        ViewData["Csrf"] = csrf;
        return View("Approve");
    }

    [HttpGet("code/{token}.png")]
    [HttpGet("/qr-login/code/{token}.png")] // legacy alias
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
