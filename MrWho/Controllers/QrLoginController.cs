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
    private readonly IEnhancedQrLoginService _enhancedQrService;
    private readonly IQrLoginStore _store;
    private readonly UserManager<IdentityUser> _userManager;
    private readonly SignInManager<IdentityUser> _signInManager;
    private readonly ILogger<QrLoginController> _logger;
    private readonly IDynamicCookieService _dynamicCookieService;

    public QrLoginController(
        IEnhancedQrLoginService enhancedQrService,
        IQrLoginStore store,
        UserManager<IdentityUser> userManager,
        SignInManager<IdentityUser> signInManager,
        IDynamicCookieService dynamicCookieService,
        ILogger<QrLoginController> logger)
    {
        _enhancedQrService = enhancedQrService;
        _store = store;
        _userManager = userManager;
        _signInManager = signInManager;
        _dynamicCookieService = dynamicCookieService;
        _logger = logger;
    }

    [HttpGet("start")]
    [AllowAnonymous]
    public async Task<IActionResult> Start(string? returnUrl = null, string? clientId = null, bool persistent = false)
    {
        string token;
        
        if (persistent)
        {
            // Create persistent QR session
            token = await _enhancedQrService.CreatePersistentQrAsync(
                userId: null, // Will be set when approved
                clientId: clientId,
                returnUrl: returnUrl,
                ttl: TimeSpan.FromMinutes(5)
            );
            _logger.LogDebug("Created persistent QR session with token {Token}", token);
        }
        else
        {
            // Create session-based QR (original behavior)
            var ticket = _enhancedQrService.CreateSessionQr(returnUrl, clientId);
            token = ticket.Token;
            _logger.LogDebug("Created session QR with token {Token}", token);
        }

        ViewData["Token"] = token;
        ViewData["ReturnUrl"] = returnUrl;
        ViewData["ClientId"] = clientId;
        ViewData["IsPersistent"] = persistent;
        
        return View("Start");
    }

    [HttpGet("qr.png")]
    [AllowAnonymous]
    public IActionResult QrPng([FromQuery] string token, [FromQuery] bool persistent = false)
    {
        if (string.IsNullOrWhiteSpace(token)) 
            return BadRequest();

        string deepLink;
        if (persistent)
        {
            // For persistent QR, link to the device management approve endpoint
            deepLink = Url.Action("ApprovePersistent", "DeviceManagement", new { token }, Request.Scheme, Request.Host.ToString())!;
        }
        else
        {
            // For session QR, use the original approve endpoint
            deepLink = Url.Action("Approve", "QrLogin", new { token }, Request.Scheme, Request.Host.ToString())!;
        }

        using var generator = new QRCodeGenerator();
        var data = generator.CreateQrCode(deepLink, QRCodeGenerator.ECCLevel.Q);
        var png = new PngByteQRCode(data).GetGraphic(8);
        return File(png, "image/png");
    }

    [HttpGet("status")]
    [AllowAnonymous]
    public async Task<IActionResult> Status([FromQuery] string token)
    {
        try
        {
            var sessionInfo = await _enhancedQrService.GetQrSessionInfoAsync(token);
            var approved = sessionInfo.Status == QrSessionStatusEnum.Approved || 
                         sessionInfo.Status == QrSessionStatusEnum.Completed;

            return Json(new { 
                approved, 
                status = sessionInfo.Status.ToString(),
                deviceName = sessionInfo.DeviceName,
                approvedAt = sessionInfo.ApprovedAt
            });
        }
        catch (ArgumentException)
        {
            return NotFound(new { status = "expired" });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting QR status for token {Token}", token);
            return Json(new { approved = false, status = "error" });
        }
    }

    [HttpGet("approve")]
    [Authorize]
    public async Task<IActionResult> Approve([FromQuery] string token)
    {
        try
        {
            var sessionInfo = await _enhancedQrService.GetQrSessionInfoAsync(token);
            if (sessionInfo.Status != QrSessionStatusEnum.Pending)
            {
                return View("Approve", model: "expired");
            }

            var user = await _userManager.GetUserAsync(User);
            if (user == null) 
                return Challenge();

            var success = await _enhancedQrService.ApproveQrAsync(token, user.Id);
            if (!success)
            {
                return View("Approve", model: "expired");
            }

            _logger.LogInformation("QR session {Token} approved by user {UserId}", token, user.Id);
            return View("Approve", model: "approved");
        }
        catch (ArgumentException)
        {
            return View("Approve", model: "expired");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error approving QR session {Token}", token);
            return View("Approve", model: "error");
        }
    }

    [HttpPost("complete")]
    [AllowAnonymous]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Complete([FromForm] string token)
    {
        if (string.IsNullOrEmpty(token))
            return BadRequest();

        try
        {
            var sessionInfo = await _enhancedQrService.GetQrSessionInfoAsync(token);
            
            if (sessionInfo.Status != QrSessionStatusEnum.Approved)
            {
                _logger.LogDebug("QR session {Token} not approved, current status: {Status}", token, sessionInfo.Status);
                return RedirectToAction("Start");
            }

            if (string.IsNullOrEmpty(sessionInfo.UserId))
            {
                _logger.LogWarning("QR session {Token} approved but no user ID", token);
                return RedirectToAction("Start");
            }

            var user = await _userManager.FindByIdAsync(sessionInfo.UserId);
            if (user == null)
            {
                _logger.LogWarning("User {UserId} not found for approved QR session {Token}", sessionInfo.UserId, token);
                return RedirectToAction("Start");
            }

            // Sign in the user
            await _signInManager.SignInAsync(user, isPersistent: false);

            // If we have a client ID, sign in with client-specific cookie using the dynamic service
            if (!string.IsNullOrEmpty(sessionInfo.ClientId))
            {
                try
                {
                    await _dynamicCookieService.SignInWithClientCookieAsync(sessionInfo.ClientId, user, false);
                    _logger.LogDebug("Signed in user {UserName} with client-specific cookie for client {ClientId}", 
                        user.UserName, sessionInfo.ClientId);
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Failed to sign in with client-specific cookie for client {ClientId}", sessionInfo.ClientId);
                }
            }

            // Mark session as completed
            await _enhancedQrService.CompleteQrAsync(token);

            _logger.LogInformation("QR login completed for user {UserName} (session: {Token})", user.UserName, token);

            // Redirect to the original return URL
            if (!string.IsNullOrEmpty(sessionInfo.ReturnUrl))
            {
                if (sessionInfo.ReturnUrl.Contains("/connect/authorize"))
                {
                    _logger.LogDebug("QR login successful, redirecting to OIDC authorization endpoint: {ReturnUrl}", sessionInfo.ReturnUrl);
                    return Redirect(sessionInfo.ReturnUrl);
                }
                else if (Url.IsLocalUrl(sessionInfo.ReturnUrl))
                {
                    _logger.LogDebug("QR login successful, redirecting to local URL: {ReturnUrl}", sessionInfo.ReturnUrl);
                    return Redirect(sessionInfo.ReturnUrl);
                }
            }

            _logger.LogDebug("QR login successful, redirecting to Home");
            return RedirectToAction("Index", "Home");
        }
        catch (ArgumentException)
        {
            _logger.LogDebug("QR session {Token} not found or expired", token);
            return RedirectToAction("Start");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error completing QR session {Token}", token);
            return RedirectToAction("Start");
        }
    }
}
