using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using MrWho.Services;
using QRCoder;
using Microsoft.AspNetCore.Identity;

namespace MrWho.Controllers;

[Route("qr")]
public class QrController : Controller
{
    private readonly IPersistentQrLoginService _qr;
    private readonly SignInManager<IdentityUser> _signInManager;
    private readonly UserManager<IdentityUser> _userManager;
    private readonly ILogger<QrController> _logger;

    public QrController(IPersistentQrLoginService qr, SignInManager<IdentityUser> signInManager, UserManager<IdentityUser> userManager, ILogger<QrController> logger)
    {
        _qr = qr; _signInManager = signInManager; _userManager = userManager; _logger = logger;
    }

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

    [HttpGet("status/{token}")]
    [HttpGet("/qr-login/status/{token}")] // legacy alias
    [AllowAnonymous]
    public async Task<IActionResult> Status(string token)
    {
        var dto = await _qr.GetAsync(token);
        if (dto == null) return NotFound(new { status = "expired" });
        return Json(new { status = dto.Status.ToString(), approved = dto.Status == MrWho.Shared.QrSessionStatus.Approved, completed = dto.Status == MrWho.Shared.QrSessionStatus.Completed });
    }

    [HttpPost("complete")]
    [HttpPost("/qr-login/complete")] // legacy alias
    [AllowAnonymous]
    public async Task<IActionResult> Complete([FromForm] string token, [FromForm] string csrf)
    {
        var dto = await _qr.GetAsync(token);
        if (dto == null) return NotFound();
        if (dto.Status != MrWho.Shared.QrSessionStatus.Approved) return BadRequest(new { error = "not_approved" });
        if (string.IsNullOrEmpty(dto.UserId)) return BadRequest(new { error = "no_user" });
        var user = await _userManager.FindByIdAsync(dto.UserId);
        if (user == null) return BadRequest(new { error = "user_not_found" });

        await _signInManager.SignInAsync(user, isPersistent: false);
        await _qr.CompleteAsync(token, csrf);

        if (!string.IsNullOrEmpty(dto.ReturnUrl))
        {
            if (dto.ReturnUrl.Contains("/connect/authorize", StringComparison.OrdinalIgnoreCase)) return Redirect(dto.ReturnUrl);
            if (Url.IsLocalUrl(dto.ReturnUrl)) return Redirect(dto.ReturnUrl);
        }
        return RedirectToAction("Index", "Home");
    }

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
        var approveUrl = Url.Action("Approve", "Qr", new { token, csrf }, Request.Scheme, Request.Host.ToString());
        using var generator = new QRCodeGenerator();
        var data = generator.CreateQrCode(approveUrl, QRCodeGenerator.ECCLevel.Q);
        var png = new PngByteQRCode(data).GetGraphic(8);
        return File(png, "image/png");
    }
}
