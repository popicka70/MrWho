using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Text;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using MrWho.Services;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using MrWho.Data;

namespace MrWho.Controllers;

[Authorize]
[Route("mfa")]
public class MfaController : Controller
{
    private readonly UserManager<IdentityUser> _userManager;
    private readonly SignInManager<IdentityUser> _signInManager;
    private readonly UrlEncoder _urlEncoder;
    private readonly IQrCodeService _qr;
    private readonly IDynamicCookieService _dynamicCookieService;
    private readonly ILogger<MfaController> _logger;
    private readonly ApplicationDbContext _db;
    private readonly ITimeLimitedDataProtector _mfaProtector;
    private readonly ISecurityAuditWriter _audit;
    private const string MfaCookiePrefix = ".MrWho.Mfa.";

    private const string AuthenticatorUriFormat = "otpauth://totp/{0}:{1}?secret={2}&issuer={0}&digits=6";

    public MfaController(UserManager<IdentityUser> userManager,
                         SignInManager<IdentityUser> signInManager,
                         UrlEncoder urlEncoder,
                         IQrCodeService qr,
                         IDynamicCookieService dynamicCookieService,
                         ILogger<MfaController> logger,
                         ApplicationDbContext db,
                         IDataProtectionProvider dataProtectionProvider,
                         ISecurityAuditWriter audit)
    {
        _userManager = userManager;
        _signInManager = signInManager;
        _urlEncoder = urlEncoder;
        _qr = qr;
        _dynamicCookieService = dynamicCookieService;
        _logger = logger;
        _db = db;
        _mfaProtector = dataProtectionProvider.CreateProtector("MrWho.MfaCookie").ToTimeLimitedDataProtector();
        _audit = audit;
    }

    [HttpGet("setup")]
    public async Task<IActionResult> Setup([FromQuery] string? returnUrl = null)
    {
        var user = await _userManager.GetUserAsync(User);
        if (user is null) return Challenge();

        var key = await _userManager.GetAuthenticatorKeyAsync(user);
        if (string.IsNullOrEmpty(key))
        {
            await _userManager.ResetAuthenticatorKeyAsync(user);
            key = await _userManager.GetAuthenticatorKeyAsync(user);
        }

        var email = await _userManager.GetEmailAsync(user) ?? await _userManager.GetUserNameAsync(user);
        var issuer = _urlEncoder.Encode("MrWho");
        var account = _urlEncoder.Encode(email ?? user.Id);
        var uri = string.Format(AuthenticatorUriFormat, issuer, account, key);
        var qrDataUri = _qr.GeneratePngDataUri(uri);

        ViewData["ReturnUrl"] = returnUrl; // propagate to the view so it can post it back

        return View("Setup", new SetupMfaViewModel
        {
            SharedKey = FormatKey(key!),
            AuthenticatorUri = uri,
            QrCodeDataUri = qrDataUri
        });
    }

    [HttpPost("verify")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Verify([FromForm] VerifyMfaInput input)
    {
        if (!ModelState.IsValid)
        {
            ViewData["ReturnUrl"] = input.ReturnUrl; // preserve returnUrl on redisplay
            return await RebuildSetupViewAsync();
        }

        var user = await _userManager.GetUserAsync(User);
        if (user is null) return Challenge();

        var code = input.Code?.Replace(" ", string.Empty).Replace("-", string.Empty);
        var isValid = await _userManager.VerifyTwoFactorTokenAsync(
            user, _userManager.Options.Tokens.AuthenticatorTokenProvider, code!);

        if (!isValid)
        {
            ModelState.AddModelError(string.Empty, "Invalid verification code.");
            ViewData["ReturnUrl"] = input.ReturnUrl; // preserve
            try { await _audit.WriteAsync(SecurityAudit.MfaVerifyFailed, new { userId = user?.Id }); } catch { }
            return await RebuildSetupViewAsync();
        }

        await _userManager.SetTwoFactorEnabledAsync(user, true);
        _logger.LogInformation("User {UserId} enabled MFA.", user.Id);
        try { await _audit.WriteAsync(SecurityAudit.MfaEnabled, new { userId = user.Id }); } catch { }

        var recoveryCodes = await _userManager.GenerateNewTwoFactorRecoveryCodesAsync(user, 10);
        ViewData["ReturnUrl"] = input.ReturnUrl; // pass to RecoveryCodes page
        return View("RecoveryCodes", (recoveryCodes ?? Enumerable.Empty<string>()).ToArray());
    }

    private async Task<IActionResult> RebuildSetupViewAsync()
    {
        var user = await _userManager.GetUserAsync(User);
        if (user is null) return Challenge();

        var key = await _userManager.GetAuthenticatorKeyAsync(user);
        if (string.IsNullOrEmpty(key))
        {
            await _userManager.ResetAuthenticatorKeyAsync(user);
            key = await _userManager.GetAuthenticatorKeyAsync(user);
        }

        var email = await _userManager.GetEmailAsync(user) ?? await _userManager.GetUserNameAsync(user);
        var issuer = _urlEncoder.Encode("MrWho");
        var account = _urlEncoder.Encode(email ?? user.Id);
        var uri = string.Format(AuthenticatorUriFormat, issuer, account, key);
        var qrDataUri = _qr.GeneratePngDataUri(uri);

        return View("Setup", new SetupMfaViewModel
        {
            SharedKey = FormatKey(key!),
            AuthenticatorUri = uri,
            QrCodeDataUri = qrDataUri
        });
    }

    [HttpGet("recovery-codes")]
    public async Task<IActionResult> RecoveryCodes()
    {
        var user = await _userManager.GetUserAsync(User);
        if (user is null) return Challenge();
        var codes = await _userManager.GenerateNewTwoFactorRecoveryCodesAsync(user, 10);
        return View("RecoveryCodes", (codes ?? Enumerable.Empty<string>()).ToArray());
    }

    [HttpPost("disable")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Disable()
    {
        var user = await _userManager.GetUserAsync(User);
        if (user is null) return Challenge();
        await _userManager.SetTwoFactorEnabledAsync(user, false);
        await _userManager.ResetAuthenticatorKeyAsync(user);
        _logger.LogInformation("User {UserId} disabled MFA.", user.Id);
        try { await _audit.WriteAsync(SecurityAudit.MfaDisabled, new { userId = user.Id }); } catch { }
        return Redirect("/profile");
    }

    [AllowAnonymous]
    [HttpGet("challenge")]
    public IActionResult ChallengeMfa(string? returnUrl = null, bool RememberMe = false)
    {
        return View("Challenge", new VerifyMfaInput { ReturnUrl = returnUrl, RememberMe = RememberMe });
    }

    [AllowAnonymous]
    [HttpPost("challenge")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> ChallengeMfaPost([FromForm] VerifyMfaInput input)
    {
        if (!ModelState.IsValid)
            return View("Challenge", input);

        var normalized = input.Code?.Replace(" ", string.Empty).Replace("-", string.Empty);
        if (string.IsNullOrWhiteSpace(normalized))
        {
            ModelState.AddModelError(string.Empty, "Invalid code.");
            return View("Challenge", input);
        }

        IdentityUser? verifiedUser = null;

        // Preferred path: verify against the currently authenticated user (step-up scenario)
        try
        {
            var currentUser = await _userManager.GetUserAsync(User);
            if (currentUser != null)
            {
                var ok = await _userManager.VerifyTwoFactorTokenAsync(currentUser, _userManager.Options.Tokens.AuthenticatorTokenProvider, normalized);
                if (ok)
                {
                    verifiedUser = currentUser;
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Direct TOTP verification against current user failed; will try TwoFactor cookie flow.");
        }

        // Fallback: use Identity's two-factor cookie flow if present
        if (verifiedUser == null)
        {
            var result = await _signInManager.TwoFactorAuthenticatorSignInAsync(normalized, input.RememberMe, input.RememberMachine);
            if (result.Succeeded)
            {
                try { verifiedUser = await _signInManager.GetTwoFactorAuthenticationUserAsync(); }
                catch { verifiedUser = null; }
            }
        }

        if (verifiedUser == null)
        {
            ModelState.AddModelError(string.Empty, "Invalid code.");
            try { await _audit.WriteAsync(SecurityAudit.MfaChallengeFailed, new { userId = verifiedUser?.Id, returnUrl = input.ReturnUrl }); } catch { }
            return View("Challenge", input);
        }

        // Sign-in/update AMR so the OP can issue tokens with amr=mfa
        await _signInManager.SignInAsync(verifiedUser, isPersistent: input.RememberMe, authenticationMethod: "mfa");
        try { await _audit.WriteAsync(SecurityAudit.MfaChallengeSuccess, new { userId = verifiedUser.Id, returnUrl = input.ReturnUrl }); } catch { }

        // Extract client_id from returnUrl to create client-specific cookie and grace cookie
        string? clientId = null;
        if (!string.IsNullOrEmpty(input.ReturnUrl) && input.ReturnUrl.Contains("/connect/authorize"))
        {
            try
            {
                var uri = new Uri(input.ReturnUrl);
                var queryParams = System.Web.HttpUtility.ParseQueryString(uri.Query);
                clientId = queryParams["client_id"];

                if (!string.IsNullOrEmpty(clientId))
                {
                    try
                    {
                        await _dynamicCookieService.SignInWithClientCookieAsync(clientId, verifiedUser, input.RememberMe);

                        var dbClient = await _db.Clients.Include(c => c.Realm).FirstOrDefaultAsync(c => c.ClientId == clientId);
                        if (dbClient != null)
                        {
                            var remember = dbClient.RememberMfaForSession ?? dbClient.Realm?.DefaultRememberMfaForSession ?? true;
                            var graceMinutes = dbClient.MfaGracePeriodMinutes ?? dbClient.Realm?.DefaultMfaGracePeriodMinutes ?? 60;
                            if (remember && graceMinutes > 0)
                            {
                                // Indicate the specific MFA method used: 'totp' for authenticator app
                                var payload = $"v1|totp|{DateTimeOffset.UtcNow.ToUnixTimeSeconds()}";
                                var protectedValue = _mfaProtector.Protect(payload, lifetime: TimeSpan.FromMinutes(graceMinutes));
                                var cookieName = MfaCookiePrefix + clientId;
                                Response.Cookies.Append(cookieName, protectedValue, new CookieOptions
                                {
                                    HttpOnly = true,
                                    Secure = true,
                                    SameSite = SameSiteMode.Lax,
                                    Expires = DateTimeOffset.UtcNow.AddMinutes(graceMinutes),
                                    IsEssential = true
                                });
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning(ex, "Failed client-specific cookie sign-in for client {ClientId}", clientId);
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to parse client_id from return URL {ReturnUrl}", input.ReturnUrl);
            }
        }

        if (input.RememberMachine)
        {
            try { await _signInManager.RememberTwoFactorClientAsync(verifiedUser); }
            catch (Exception ex) { _logger.LogDebug(ex, "Remember device failed"); }
        }

        if (!string.IsNullOrEmpty(input.ReturnUrl))
        {
            if (Url.IsLocalUrl(input.ReturnUrl) || input.ReturnUrl.Contains("/connect/authorize", StringComparison.OrdinalIgnoreCase))
                return Redirect(input.ReturnUrl);
        }
        return Redirect("/");
    }

    private static string FormatKey(string unformattedKey)
    {
        var result = new StringBuilder();
        int currentPosition = 0;
        while (currentPosition + 4 < unformattedKey.Length)
        {
            result.Append(unformattedKey.AsSpan(currentPosition, 4)).Append(' ');
            currentPosition += 4;
        }
        if (currentPosition < unformattedKey.Length)
        {
            result.Append(unformattedKey.AsSpan(currentPosition));
        }
        return result.ToString().ToLowerInvariant();
    }
}

public sealed class SetupMfaViewModel
{
    public string SharedKey { get; set; } = string.Empty;
    public string AuthenticatorUri { get; set; } = string.Empty;
    public string QrCodeDataUri { get; set; } = string.Empty;
}

public sealed class VerifyMfaInput
{
    [Required]
    [StringLength(7, MinimumLength = 6)]
    public string? Code { get; set; }

    public string? ReturnUrl { get; set; }
    public bool RememberMe { get; set; }
    public bool RememberMachine { get; set; }
}
