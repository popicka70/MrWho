using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using OpenIddict.Client.AspNetCore;
using Microsoft.AspNetCore.Identity;
using System.Security.Claims;
using MrWho.Services;
using MrWho.Data;

namespace MrWho.Controllers;

[ApiController]
[Route("connect/external")] // Matches redirection endpoints configured in client registrations
public class ExternalAuthController : ControllerBase
{
    private readonly UserManager<IdentityUser> _userManager;
    private readonly SignInManager<IdentityUser> _signInManager;
    private readonly IDynamicCookieService _dynamicCookieService;
    private readonly ILogger<ExternalAuthController> _logger;

    public ExternalAuthController(
        UserManager<IdentityUser> userManager,
        SignInManager<IdentityUser> signInManager,
        IDynamicCookieService dynamicCookieService,
        ILogger<ExternalAuthController> logger)
    {
        _userManager = userManager;
        _signInManager = signInManager;
        _dynamicCookieService = dynamicCookieService;
        _logger = logger;
    }

    [HttpGet("callback")]
    [IgnoreAntiforgeryToken]
    public async Task<IActionResult> Callback()
    {
        // Authenticate the result from the OpenIddict client
        var result = await HttpContext.AuthenticateAsync(OpenIddictClientAspNetCoreDefaults.AuthenticationScheme);
        if (!result.Succeeded)
        {
            _logger.LogWarning("External authentication failed: {Failure}", result.Failure?.Message);
            return Unauthorized(new { error = result.Failure?.Message });
        }

        // Persist the RegistrationId of the external provider in session for future sign-out
        try
        {
            string? regId = null;
            if (result.Properties?.Items != null)
            {
                // Prefer custom roundtripped id if present
                if (result.Properties.Items.TryGetValue("extRegistrationId", out var regIdCustom) && !string.IsNullOrWhiteSpace(regIdCustom))
                {
                    regId = regIdCustom;
                }
                else if (result.Properties.Items.TryGetValue(OpenIddictClientAspNetCoreConstants.Properties.RegistrationId, out var regIdStd) && !string.IsNullOrWhiteSpace(regIdStd))
                {
                    regId = regIdStd;
                }
            }
            if (!string.IsNullOrWhiteSpace(regId))
            {
                HttpContext.Session.SetString("ExternalRegistrationId", regId);
                _logger.LogDebug("Stored external RegistrationId in session: {RegistrationId}", regId);
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Failed to store external RegistrationId in session");
        }

        // Extract returnUrl/clientId from properties if carried over, otherwise from query
        string? returnUrl = null;
        string? clientId = null;
        if (result.Properties?.Items != null)
        {
            result.Properties.Items.TryGetValue("returnUrl", out returnUrl);
            result.Properties.Items.TryGetValue("clientId", out clientId);
        }
        returnUrl ??= Request.Query["returnUrl"].ToString();
        clientId ??= Request.Query["clientId"].ToString();

        var principal = result.Principal!;
        var email = principal.FindFirst("email")?.Value
                    ?? principal.FindFirst("preferred_username")?.Value
                    ?? principal.Identity?.Name;
        var subject = principal.FindFirst("sub")?.Value;
        if (string.IsNullOrWhiteSpace(email))
        {
            // Fallback to a synthetic username if no email/username
            email = subject ?? $"external_user_{Guid.NewGuid():N}";
        }

        // Find or create local user
        var user = await _userManager.FindByEmailAsync(email) ?? await _userManager.FindByNameAsync(email);
        if (user == null)
        {
            user = new IdentityUser
            {
                UserName = email,
                Email = email,
                EmailConfirmed = true
            };
            var create = await _userManager.CreateAsync(user);
            if (!create.Succeeded)
            {
                _logger.LogError("Failed to create local user for external login: {Errors}", string.Join(", ", create.Errors.Select(e => e.Description)));
                return StatusCode(500, new { error = "Failed to create local user" });
            }

            // Optionally store basic name claims
            var name = principal.FindFirst("name")?.Value;
            var given = principal.FindFirst("given_name")?.Value;
            var family = principal.FindFirst("family_name")?.Value;
            var claims = new List<Claim>();
            if (!string.IsNullOrWhiteSpace(name)) claims.Add(new Claim("name", name));
            if (!string.IsNullOrWhiteSpace(given)) claims.Add(new Claim("given_name", given));
            if (!string.IsNullOrWhiteSpace(family)) claims.Add(new Claim("family_name", family));
            if (claims.Count > 0)
            {
                await _userManager.AddClaimsAsync(user, claims);
            }
        }

        // Sign in locally
        await _signInManager.SignInAsync(user, isPersistent: false);

        // Also create client-specific cookie if clientId provided
        if (!string.IsNullOrEmpty(clientId))
        {
            try
            {
                await _dynamicCookieService.SignInWithClientCookieAsync(clientId, user, rememberMe: false);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to sign in with client cookie for client {ClientId}", clientId);
            }
        }

        // Redirect back to original OIDC authorization or local URL
        if (!string.IsNullOrEmpty(returnUrl))
        {
            if (returnUrl.Contains("/connect/authorize", StringComparison.OrdinalIgnoreCase))
            {
                return Redirect(returnUrl);
            }
            if (Url.IsLocalUrl(returnUrl))
            {
                return Redirect(returnUrl);
            }
        }

        return RedirectToAction("Index", "Home");
    }

    [HttpGet("signout-callback")]
    [IgnoreAntiforgeryToken]
    public IActionResult SignoutCallback([FromQuery] string? returnUrl = null)
    {
        // Clear the external registration marker so we don't attempt sign-out again
        try
        {
            HttpContext.Session.Remove("ExternalRegistrationId");
        }
        catch { /* ignore */ }

        if (!string.IsNullOrEmpty(returnUrl))
        {
            return Redirect(returnUrl);
        }

        return Ok(new { Message = "External sign-out completed" });
    }
}
