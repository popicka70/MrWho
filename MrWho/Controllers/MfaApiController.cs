using System.ComponentModel.DataAnnotations;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using MrWho.Services;

namespace MrWho.Controllers;

/// <summary>
/// JSON API for MFA (TOTP authenticator) enrollment and management.
/// Intended for Blazor/SPA consumption. Mirrors logic in MVC MfaController.
/// </summary>
[Authorize]
[ApiController]
[Route("api/mfa")] // Base path for MFA API
public class MfaApiController : ControllerBase
{
    private readonly UserManager<IdentityUser> _userManager;
    private readonly UrlEncoder _urlEncoder;
    private readonly IQrCodeService _qr;
    private readonly ILogger<MfaApiController> _logger;

    private const string AuthenticatorUriFormat = "otpauth://totp/{0}:{1}?secret={2}&issuer={0}&digits=6";

    public MfaApiController(UserManager<IdentityUser> userManager,
                            UrlEncoder urlEncoder,
                            IQrCodeService qr,
                            ILogger<MfaApiController> logger)
    {
        _userManager = userManager;
        _urlEncoder = urlEncoder;
        _qr = qr;
        _logger = logger;
    }

    /// <summary>
    /// Begin (or resume) authenticator setup. Returns secret/key and QR code.
    /// If the user already has an authenticator key assigned we reuse it (allows re-display)
    /// </summary>
    [HttpGet("setup")] // GET api/mfa/setup
    public async Task<ActionResult<MfaSetupResponse>> GetSetup()
    {
        var user = await _userManager.GetUserAsync(User);
        if (user is null) {
            return Unauthorized();
        }

        // Reuse existing key or create a new one if none
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

        return Ok(new MfaSetupResponse
        {
            SharedKey = FormatKey(key!),
            AuthenticatorUri = uri,
            QrCodeDataUri = qrDataUri,
            TwoFactorEnabled = user.TwoFactorEnabled
        });
    }

    /// <summary>
    /// Verify the code from the authenticator app and enable 2FA.
    /// Returns recovery codes on first successful enable.
    /// </summary>
    [HttpPost("verify")] // POST api/mfa/verify
    public async Task<ActionResult<MfaVerifyResponse>> PostVerify([FromBody] MfaVerifyRequest request)
    {
        if (!ModelState.IsValid) {
            return ValidationProblem(ModelState);
        }

        var user = await _userManager.GetUserAsync(User);
        if (user is null) {
            return Unauthorized();
        }

        var code = request.Code?.Replace(" ", string.Empty).Replace("-", string.Empty);
        var isValid = await _userManager.VerifyTwoFactorTokenAsync(
            user, _userManager.Options.Tokens.AuthenticatorTokenProvider, code!);

        if (!isValid)
        {
            return Ok(new MfaVerifyResponse
            {
                Success = false,
                Error = "Invalid verification code"
            });
        }

        // Enable if not already
        if (!user.TwoFactorEnabled)
        {
            await _userManager.SetTwoFactorEnabledAsync(user, true);
            _logger.LogInformation("User {UserId} enabled MFA via API.", user.Id);
        }

        // Generate recovery codes (only if user has none or explicitly requested regeneration)
        string[]? recoveryCodes = null;
        if (request.GenerateNewRecoveryCodes || !user.TwoFactorEnabled)
        {
            recoveryCodes = (await _userManager.GenerateNewTwoFactorRecoveryCodesAsync(user, 10))?.ToArray();
        }
        else if (request.GenerateNewRecoveryCodes)
        {
            recoveryCodes = (await _userManager.GenerateNewTwoFactorRecoveryCodesAsync(user, 10))?.ToArray();
        }

        return Ok(new MfaVerifyResponse
        {
            Success = true,
            RecoveryCodes = recoveryCodes
        });
    }

    /// <summary>
    /// Generate a fresh set of recovery codes (invalidates old ones).
    /// </summary>
    [HttpPost("recovery-codes")] // POST api/mfa/recovery-codes
    public async Task<ActionResult<MfaRecoveryCodesResponse>> PostNewRecoveryCodes()
    {
        var user = await _userManager.GetUserAsync(User);
        if (user is null) {
            return Unauthorized();
        }

        if (!user.TwoFactorEnabled) {
            return BadRequest("MFA not enabled");
        }

        var codes = await _userManager.GenerateNewTwoFactorRecoveryCodesAsync(user, 10);
        return Ok(new MfaRecoveryCodesResponse { RecoveryCodes = (codes ?? Enumerable.Empty<string>()).ToArray() });
    }

    /// <summary>
    /// Disable MFA and reset secret.
    /// </summary>
    [HttpPost("disable")] // POST api/mfa/disable
    public async Task<ActionResult<MfaDisableResponse>> PostDisable()
    {
        var user = await _userManager.GetUserAsync(User);
        if (user is null) {
            return Unauthorized();
        }

        if (!user.TwoFactorEnabled)
        {
            return Ok(new MfaDisableResponse { Success = true, AlreadyDisabled = true });
        }
        await _userManager.SetTwoFactorEnabledAsync(user, false);
        await _userManager.ResetAuthenticatorKeyAsync(user);
        _logger.LogInformation("User {UserId} disabled MFA via API.", user.Id);
        return Ok(new MfaDisableResponse { Success = true, AlreadyDisabled = false });
    }

    private static string FormatKey(string unformattedKey)
    {
        var result = new System.Text.StringBuilder();
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

public sealed class MfaSetupResponse
{
    public string SharedKey { get; set; } = string.Empty;
    public string AuthenticatorUri { get; set; } = string.Empty;
    public string QrCodeDataUri { get; set; } = string.Empty;
    public bool TwoFactorEnabled { get; set; }
}

public sealed class MfaVerifyRequest
{
    [Required]
    [StringLength(7, MinimumLength = 6)]
    public string? Code { get; set; }
    public bool GenerateNewRecoveryCodes { get; set; }
}

public sealed class MfaVerifyResponse
{
    public bool Success { get; set; }
    public string? Error { get; set; }
    public string[]? RecoveryCodes { get; set; }
}

public sealed class MfaRecoveryCodesResponse
{
    public string[] RecoveryCodes { get; set; } = Array.Empty<string>();
}

public sealed class MfaDisableResponse
{
    public bool Success { get; set; }
    public bool AlreadyDisabled { get; set; }
}
