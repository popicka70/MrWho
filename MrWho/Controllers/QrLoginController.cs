using System.Text;
using System.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using MrWho.Services;
using QRCoder;

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
    private readonly IUserRealmValidationService _realmValidationService; // added

    public QrLoginController(
        IEnhancedQrLoginService enhancedQrService,
        IQrLoginStore store,
        UserManager<IdentityUser> userManager,
        SignInManager<IdentityUser> signInManager,
        IDynamicCookieService dynamicCookieService,
        IUserRealmValidationService realmValidationService, // added
        ILogger<QrLoginController> logger)
    {
        _enhancedQrService = enhancedQrService;
        _store = store;
        _userManager = userManager;
        _signInManager = signInManager;
        _dynamicCookieService = dynamicCookieService;
        _realmValidationService = realmValidationService; // added
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
        if (string.IsNullOrWhiteSpace(token)) {
            return BadRequest();
        }

        string deepLink;
        if (persistent)
        {
            // NEW: force login first for persistent QR approval as well
            var approvePersistentRelative = Url.Action("ApprovePersistent", "DeviceManagementWeb", new { token });
            var encodedReturn = Uri.EscapeDataString(approvePersistentRelative ?? $"/device-management/approve-persistent/{Uri.EscapeDataString(token)}");
            deepLink = $"{Request.Scheme}://{Request.Host}/connect/login?returnUrl={encodedReturn}";
            _logger.LogDebug("Persistent QR deep link (login first) generated for token {Token}: {DeepLink}", token, deepLink);
        }
        else
        {
            // For session QR, force user through the login endpoint first.
            var approveRelative = Url.Action("Approve", "QrLogin", new { token });
            var encodedReturn = Uri.EscapeDataString(approveRelative ?? $"/qr-login/approve?token={Uri.EscapeDataString(token)}");
            deepLink = $"{Request.Scheme}://{Request.Host}/connect/login?returnUrl={encodedReturn}";
            _logger.LogDebug("Session QR deep link (login first) generated for token {Token}: {DeepLink}", token, deepLink);
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

            return Json(new
            {
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
            if (user is null)
            {
                return Redirect($"/connect/login?returnUrl={HttpUtility.UrlEncode(Request.Path + Request.QueryString)}");
            }

            // Eligibility check when clientId present
            if (!string.IsNullOrEmpty(sessionInfo.ClientId))
            {
                try
                {
                    var validation = await _realmValidationService.ValidateUserRealmAccessAsync(user, sessionInfo.ClientId);
                    if (!validation.IsValid)
                    {
                        _logger.LogWarning("QR login approval denied: user {User} not eligible for client {ClientId}. Reason: {Reason}", user.UserName, sessionInfo.ClientId, validation.Reason);
                        ViewData["Token"] = token;
                        ViewData["SessionInfo"] = sessionInfo;
                        ViewData["UserName"] = user.UserName;
                        return View("Approve", model: "denied");
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error validating eligibility for user {User} and client {ClientId} during QR approve GET", user.Id, sessionInfo.ClientId);
                    return View("Approve", model: "error");
                }
            }

            ViewData["Token"] = token;
            ViewData["SessionInfo"] = sessionInfo;
            ViewData["UserName"] = user.UserName;

            return View("Approve", model: "pending");
        }
        catch (ArgumentException)
        {
            return View("Approve", model: "expired");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error loading QR approval page for token {Token}", token);
            return View("Approve", model: "error");
        }
    }

    [HttpPost("approve")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> ApprovePost([FromForm] string token, [FromForm] string action)
    {
        var user = await _userManager.GetUserAsync(User);
        if (user == null) {
            return Challenge();
        }

        try
        {
            // Get session info to perform status and client eligibility checks
            var sessionInfo = await _enhancedQrService.GetQrSessionInfoAsync(token);
            if (sessionInfo.Status != QrSessionStatusEnum.Pending)
            {
                return View("Approve", model: "expired");
            }

            if (action == "approve")
            {
                if (!string.IsNullOrEmpty(sessionInfo.ClientId))
                {
                    try
                    {
                        var validation = await _realmValidationService.ValidateUserRealmAccessAsync(user, sessionInfo.ClientId);
                        if (!validation.IsValid)
                        {
                            _logger.LogWarning("QR login approval denied (POST): user {User} not eligible for client {ClientId}. Reason: {Reason}", user.UserName, sessionInfo.ClientId, validation.Reason);
                            return View("Approve", model: "denied");
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, "Error validating eligibility for user {User} and client {ClientId} during QR approve POST", user.Id, sessionInfo.ClientId);
                        return View("Approve", model: "error");
                    }
                }

                var success = await _enhancedQrService.ApproveQrAsync(token, user.Id);
                if (!success)
                {
                    return View("Approve", model: "expired");
                }

                _logger.LogInformation("QR session {Token} approved by user {UserId}", token, user.Id);
                return View("Approve", model: "approved");
            }
            else if (action == "reject")
            {
                _logger.LogInformation("QR session {Token} rejected by user {UserId}", token, user.Id);
                return View("Approve", model: "rejected");
            }
            else
            {
                return BadRequest("Invalid action.");
            }
        }
        catch (ArgumentException)
        {
            return View("Approve", model: "expired");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error processing QR approval for token {Token}", token);
            return View("Approve", model: "error");
        }
    }

    [HttpPost("complete")]
    [AllowAnonymous]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Complete([FromForm] string token)
    {
        if (string.IsNullOrEmpty(token)) {
            return BadRequest();
        }

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

            // Re-validate eligibility at completion time (user could have been revoked meanwhile)
            if (!string.IsNullOrEmpty(sessionInfo.ClientId))
            {
                try
                {
                    var validation = await _realmValidationService.ValidateUserRealmAccessAsync(user, sessionInfo.ClientId);
                    if (!validation.IsValid)
                    {
                        _logger.LogWarning("QR login completion denied: user {User} not eligible for client {ClientId}. Reason: {Reason}", user.UserName, sessionInfo.ClientId, validation.Reason);
                        return Redirect(BuildAccessDeniedUrl(sessionInfo.ReturnUrl, sessionInfo.ClientId));
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error validating eligibility for user {User} and client {ClientId} during QR completion", user.Id, sessionInfo.ClientId);
                    return Redirect(BuildAccessDeniedUrl(sessionInfo.ReturnUrl, sessionInfo.ClientId));
                }
            }

            await _signInManager.SignInAsync(user, isPersistent: false);

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

            await _enhancedQrService.CompleteQrAsync(token);

            _logger.LogInformation("QR login completed for user {UserName} (session: {Token})", user.UserName, token);

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

    private static string BuildAccessDeniedUrl(string? returnUrl, string? clientId)
    {
        var ret = !string.IsNullOrEmpty(returnUrl) ? Uri.EscapeDataString(returnUrl) : string.Empty;
        var cid = !string.IsNullOrEmpty(clientId) ? Uri.EscapeDataString(clientId) : string.Empty;
        var url = "/connect/access-denied";
        var hasQuery = false;
        if (!string.IsNullOrEmpty(ret)) { url += $"?returnUrl={ret}"; hasQuery = true; }
        if (!string.IsNullOrEmpty(cid)) { url += hasQuery ? $"&clientId={cid}" : $"?clientId={cid}"; }
        return url;
    }
}
