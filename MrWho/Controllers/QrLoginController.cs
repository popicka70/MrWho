using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using MrWho.Services;
using QRCoder;
using System.Text;

namespace MrWho.Controllers;

[Route("qr-login")]
public class QrLoginController : Controller
{
    private readonly IQrLoginStore _store;
    private readonly UserManager<IdentityUser> _userManager;
    private readonly SignInManager<IdentityUser> _signInManager;
    private readonly ILogger<QrLoginController> _logger;
    private readonly IDynamicCookieService _dynamicCookieService;

    public QrLoginController(IQrLoginStore store,
                             UserManager<IdentityUser> userManager,
                             SignInManager<IdentityUser> signInManager,
                             IDynamicCookieService dynamicCookieService,
                             ILogger<QrLoginController> logger)
    {
        _store = store;
        _userManager = userManager;
        _signInManager = signInManager;
        _dynamicCookieService = dynamicCookieService;
        _logger = logger;
    }

    [HttpGet("start")]
    [AllowAnonymous]
    public IActionResult Start(string? returnUrl = null, string? clientId = null)
    {
        var ticket = _store.Create(returnUrl, clientId);
        ViewData["Token"] = ticket.Token;
        ViewData["ReturnUrl"] = returnUrl;
        ViewData["ClientId"] = clientId;
        return View("Start");
    }

    [HttpGet("qr.png")]
    [AllowAnonymous]
    public IActionResult QrPng([FromQuery] string token)
    {
        if (string.IsNullOrWhiteSpace(token)) return BadRequest();
        var deepLink = Url.Action("Approve", "QrLogin", new { token }, Request.Scheme, Request.Host.ToString());
        using var generator = new QRCodeGenerator();
        var data = generator.CreateQrCode(deepLink!, QRCodeGenerator.ECCLevel.Q);
        var png = new PngByteQRCode(data).GetGraphic(8);
        return File(png, "image/png");
    }

    [HttpGet("status")]
    [AllowAnonymous]
    public IActionResult Status([FromQuery] string token)
    {
        var t = _store.Get(token);
        if (t is null) return NotFound(new { status = "expired" });
        var approved = !string.IsNullOrEmpty(t.ApprovedUserId);
        return Json(new { approved });
    }

    [HttpGet("approve")]
    [Authorize]
    public async Task<IActionResult> Approve([FromQuery] string token)
    {
        var t = _store.Get(token);
        if (t is null) return View("Approve", model: "expired");
        var user = await _userManager.GetUserAsync(User);
        if (user is null) return Challenge();
        _store.Approve(token, user.Id);
        return View("Approve", model: "ok");
    }

    [HttpPost("complete")]
    [AllowAnonymous]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Complete([FromForm] string token)
    {
        var t = _store.Get(token);
        if (t is null) return BadRequest("expired");
        if (string.IsNullOrEmpty(t.ApprovedUserId)) return Unauthorized();
        var user = await _userManager.FindByIdAsync(t.ApprovedUserId);
        if (user is null) return BadRequest("invalid-user");

        await _signInManager.SignInAsync(user, isPersistent: true, authenticationMethod: "mfa");

        if (!string.IsNullOrEmpty(t.ClientId))
        {
            try
            {
                await _dynamicCookieService.SignInWithClientCookieAsync(t.ClientId, user, rememberMe: true);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to sign in client-specific cookie for {ClientId}", t.ClientId);
            }
        }
        _store.Complete(token);

        if (!string.IsNullOrEmpty(t.ReturnUrl))
        {
            if (t.ReturnUrl.Contains("/connect/authorize") || Url.IsLocalUrl(t.ReturnUrl))
            {
                return Redirect(t.ReturnUrl);
            }
        }
        return Redirect("/");
    }
}
