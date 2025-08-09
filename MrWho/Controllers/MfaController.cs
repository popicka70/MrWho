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

namespace MrWho.Controllers;

[Authorize]
[Route("mfa")]
public class MfaController : Controller
{
    private readonly UserManager<IdentityUser> _userManager;
    private readonly SignInManager<IdentityUser> _signInManager;
    private readonly UrlEncoder _urlEncoder;
    private readonly IQrCodeService _qr;
    private readonly ILogger<MfaController> _logger;

    private const string AuthenticatorUriFormat = "otpauth://totp/{0}:{1}?secret={2}&issuer={0}&digits=6";

    public MfaController(UserManager<IdentityUser> userManager,
                         SignInManager<IdentityUser> signInManager,
                         UrlEncoder urlEncoder,
                         IQrCodeService qr,
                         ILogger<MfaController> logger)
    {
        _userManager = userManager;
        _signInManager = signInManager;
        _urlEncoder = urlEncoder;
        _qr = qr;
        _logger = logger;
    }

    [HttpGet("setup")]
    public async Task<IActionResult> Setup()
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

    [HttpPost("verify")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Verify([FromForm] VerifyMfaInput input)
    {
        if (!ModelState.IsValid) return BadRequest(ModelState);

        var user = await _userManager.GetUserAsync(User);
        if (user is null) return Challenge();

        var code = input.Code?.Replace(" ", string.Empty).Replace("-", string.Empty);
        var isValid = await _userManager.VerifyTwoFactorTokenAsync(
            user, _userManager.Options.Tokens.AuthenticatorTokenProvider, code!);

        if (!isValid)
        {
            ModelState.AddModelError(string.Empty, "Invalid verification code.");
            return View("Setup");
        }

        await _userManager.SetTwoFactorEnabledAsync(user, true);
        _logger.LogInformation("User {UserId} enabled MFA.", user.Id);

        var recoveryCodes = await _userManager.GenerateNewTwoFactorRecoveryCodesAsync(user, 10);
        return View("RecoveryCodes", recoveryCodes.ToArray());
    }

    [HttpGet("recovery-codes")]
    public async Task<IActionResult> RecoveryCodes()
    {
        var user = await _userManager.GetUserAsync(User);
        if (user is null) return Challenge();
        var codes = await _userManager.GenerateNewTwoFactorRecoveryCodesAsync(user, 10);
        return View("RecoveryCodes", codes.ToArray());
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
        return Redirect("/profile");
    }

    [AllowAnonymous]
    [HttpGet("challenge")]
    public IActionResult ChallengeMfa(string? returnUrl = null)
    {
        return View("Challenge", new VerifyMfaInput { ReturnUrl = returnUrl });
    }

    [AllowAnonymous]
    [HttpPost("challenge")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> ChallengeMfaPost([FromForm] VerifyMfaInput input)
    {
        if (!ModelState.IsValid)
            return View("Challenge", input);

        var twoFactorUser = await _signInManager.GetTwoFactorAuthenticationUserAsync();
        if (twoFactorUser is null)
            return Forbid();

        var code = input.Code?.Replace(" ", string.Empty).Replace("-", string.Empty);
        var valid = await _userManager.VerifyTwoFactorTokenAsync(
            twoFactorUser,
            _userManager.Options.Tokens.AuthenticatorTokenProvider,
            code!);

        if (!valid)
        {
            ModelState.AddModelError(string.Empty, "Invalid code.");
            return View("Challenge", input);
        }

        await _userManager.ResetAccessFailedCountAsync(twoFactorUser);

        // Sign-in and stamp the authentication method as "mfa".
        await _signInManager.SignInAsync(twoFactorUser, isPersistent: input.RememberMe, authenticationMethod: "mfa");

        if (input.RememberMachine)
        {
            await _signInManager.RememberTwoFactorClientAsync(twoFactorUser);
        }

        if (!string.IsNullOrEmpty(input.ReturnUrl) && Url.IsLocalUrl(input.ReturnUrl))
            return Redirect(input.ReturnUrl);
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
