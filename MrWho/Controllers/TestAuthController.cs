using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using MrWho.Shared;

namespace MrWho.Controllers;

[ApiController]
[Route("debug/test-signin")]
public class TestAuthController : ControllerBase
{
    private readonly UserManager<IdentityUser> _userManager;
    private readonly IAuthenticationSchemeProvider _schemes;
    private readonly ILogger<TestAuthController> _logger;

    public TestAuthController(UserManager<IdentityUser> userManager, IAuthenticationSchemeProvider schemes, ILogger<TestAuthController> logger)
    { _userManager = userManager; _schemes = schemes; _logger = logger; }

    [HttpPost]
    [AllowAnonymous]
    public async Task<IActionResult> SignInForTests([FromQuery] string userEmail, [FromQuery] string clientId)
    {
        var testEnabled = string.Equals(Environment.GetEnvironmentVariable("MRWHO_TESTS"), "1", StringComparison.OrdinalIgnoreCase) ||
                           string.Equals(Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT"), "Testing", StringComparison.OrdinalIgnoreCase);
        if (!testEnabled)
        {
            return NotFound();
        }

        if (string.IsNullOrWhiteSpace(userEmail))
        {
            return BadRequest("userEmail is required");
        }

        var user = await _userManager.FindByEmailAsync(userEmail);
        if (user == null)
        {
            return NotFound("User not found");
        }

        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, user.Id),
            new(OpenIddict.Abstractions.OpenIddictConstants.Claims.Subject, user.Id),
            new(ClaimTypes.Name, user.UserName ?? userEmail),
            new("email", user.Email ?? userEmail)
        };
        var principal = new ClaimsPrincipal(new ClaimsIdentity(claims, "test-login"));

        var defaultAuth = (await _schemes.GetDefaultAuthenticateSchemeAsync())?.Name;
        var defaultSignIn = (await _schemes.GetDefaultSignInSchemeAsync())?.Name;
        string appScheme = IdentityConstants.ApplicationScheme; // typically "Identity.Application"

        var targetSchemes = new[] { defaultAuth, defaultSignIn, appScheme }
            .Where(s => !string.IsNullOrWhiteSpace(s))
            .Distinct(StringComparer.Ordinal)
            .ToList();

        foreach (var scheme in targetSchemes)
        {
            await HttpContext.SignInAsync(scheme!, principal, new AuthenticationProperties
            {
                IsPersistent = false,
                IssuedUtc = DateTimeOffset.UtcNow,
                ExpiresUtc = DateTimeOffset.UtcNow.AddMinutes(30),
                AllowRefresh = false
            });
        }

        _logger.LogInformation("Test sign-in for {Email} issued on schemes: {Schemes} (client hint={ClientId})", userEmail, string.Join(',', targetSchemes), clientId);
        return Ok(new { schemes = targetSchemes, user = userEmail });
    }
}
