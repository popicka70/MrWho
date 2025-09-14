using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using MrWho.Data;
using MrWho.Services;
using OpenIddict.Client.AspNetCore;

namespace MrWho.Controllers;

[ApiController]
[Route("connect/external")] // Matches redirection endpoints configured in client registrations
public class ExternalAuthController : ControllerBase
{
    private readonly UserManager<IdentityUser> _userManager;
    private readonly SignInManager<IdentityUser> _signInManager;
    private readonly IDynamicCookieService _dynamicCookieService;
    private readonly ILogger<ExternalAuthController> _logger;
    private readonly ApplicationDbContext _db;
    private readonly IUserRealmValidationService _realmValidationService; // added

    public ExternalAuthController(
        UserManager<IdentityUser> userManager,
        SignInManager<IdentityUser> signInManager,
        IDynamicCookieService dynamicCookieService,
        ILogger<ExternalAuthController> logger,
        ApplicationDbContext db,
        IUserRealmValidationService realmValidationService) // added
    {
        _userManager = userManager;
        _signInManager = signInManager;
        _dynamicCookieService = dynamicCookieService;
        _logger = logger;
        _db = db;
        _realmValidationService = realmValidationService; // added
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
        string? regId = null;
        string? providerName = null;
        try
        {
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

                if (result.Properties.Items.TryGetValue("extProviderName", out var extProv) && !string.IsNullOrWhiteSpace(extProv))
                {
                    providerName = extProv;
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

        // Try durable external login link first
        IdentityUser? user = null;
        if (!string.IsNullOrWhiteSpace(regId) && !string.IsNullOrWhiteSpace(subject))
        {
            try
            {
                user = await _userManager.FindByLoginAsync(regId, subject);
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "FindByLoginAsync failed");
            }
        }

        // Fallbacks by email/username
        user ??= await _userManager.FindByEmailAsync(email) ?? await _userManager.FindByNameAsync(email);
        var newlyCreated = false;
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
            newlyCreated = true;

            // Optionally store basic name claims
            var name = principal.FindFirst("name")?.Value;
            var given = principal.FindFirst("given_name")?.Value;
            var family = principal.FindFirst("family_name")?.Value;
            var claims = new List<Claim>();
            if (!string.IsNullOrWhiteSpace(name))
            {
                claims.Add(new Claim("name", name));
            }

            if (!string.IsNullOrWhiteSpace(given))
            {
                claims.Add(new Claim("given_name", given));
            }

            if (!string.IsNullOrWhiteSpace(family))
            {
                claims.Add(new Claim("family_name", family));
            }

            if (claims.Count > 0)
            {
                await _userManager.AddClaimsAsync(user, claims);
            }

            // Create a pending registration profile so admins can approve
            try
            {
                var display = !string.IsNullOrWhiteSpace(name)
                    ? name
                    : BuildDisplayNameFromEmailOrUserName(email);

                var profile = new MrWho.Models.UserProfile
                {
                    UserId = user.Id,
                    FirstName = given,
                    LastName = family,
                    DisplayName = display,
                    State = MrWho.Models.UserState.New,
                    CreatedAt = DateTime.UtcNow
                };
                _db.UserProfiles.Add(profile);
                await _db.SaveChangesAsync();
                _logger.LogInformation("Created pending user profile for external user {UserId}", user.Id);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to create pending profile for external user {UserId}", user.Id);
            }
        }
        else
        {
            // Ensure profile exists for existing users
            try
            {
                var hasProfile = await _db.UserProfiles.AsNoTracking().AnyAsync(p => p.UserId == user.Id);
                if (!hasProfile)
                {
                    var name = principal.FindFirst("name")?.Value;
                    var given = principal.FindFirst("given_name")?.Value;
                    var family = principal.FindFirst("family_name")?.Value;
                    var display = !string.IsNullOrWhiteSpace(name)
                        ? name
                        : BuildDisplayNameFromEmailOrUserName(user.UserName ?? user.Email ?? user.Id);

                    _db.UserProfiles.Add(new MrWho.Models.UserProfile
                    {
                        UserId = user.Id,
                        FirstName = given,
                        LastName = family,
                        DisplayName = display,
                        State = MrWho.Models.UserState.New,
                        CreatedAt = DateTime.UtcNow
                    });
                    await _db.SaveChangesAsync();
                    _logger.LogInformation("Backfilled missing profile for user {UserId}", user.Id);
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to ensure profile for user {UserId}", user.Id);
            }
        }

        // Ensure the external login is linked durably
        if (!string.IsNullOrWhiteSpace(regId) && !string.IsNullOrWhiteSpace(subject))
        {
            try
            {
                var logins = await _userManager.GetLoginsAsync(user);
                if (!logins.Any(l => string.Equals(l.LoginProvider, regId, StringComparison.OrdinalIgnoreCase) && string.Equals(l.ProviderKey, subject, StringComparison.Ordinal)))
                {
                    var info = new UserLoginInfo(regId, subject, providerName ?? regId);
                    var addLogin = await _userManager.AddLoginAsync(user, info);
                    if (!addLogin.Succeeded)
                    {
                        _logger.LogWarning("AddLoginAsync failed for provider {Provider} and user {UserId}: {Errors}", regId, user.Id, string.Join(", ", addLogin.Errors.Select(e => e.Description)));
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to add external login for provider {Provider} and user {UserId}", regId, user.Id);
            }
        }

        // Persist external tokens (access/refresh/id) in Identity tokens store
        try
        {
            if (!string.IsNullOrWhiteSpace(regId))
            {
                var tokens = result.Properties?.GetTokens();
                if (tokens != null)
                {
                    foreach (var t in tokens)
                    {
                        if (!string.IsNullOrEmpty(t.Name) && !string.IsNullOrEmpty(t.Value))
                        {
                            await _userManager.SetAuthenticationTokenAsync(user, regId, t.Name, t.Value);
                        }
                    }
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Failed to persist external tokens for provider {Provider} and user {UserId}", regId, user.Id);
        }

        // Apply optional per-client claim mappings to the local user (only on first creation or always if you prefer)
        try
        {
            if (!string.IsNullOrEmpty(clientId) && !string.IsNullOrEmpty(regId))
            {
                var client = await _db.Clients.AsNoTracking().FirstOrDefaultAsync(c => c.ClientId == clientId || c.Id == clientId);
                if (client != null)
                {
                    var link = await _db.ClientIdentityProviders.AsNoTracking()
                        .Include(l => l.IdentityProvider)
                        .Where(l => l.ClientId == client.Id && l.IdentityProvider.Type == MrWho.Shared.IdentityProviderType.Oidc)
                        .FirstOrDefaultAsync(l => l.IdentityProvider.ClientId == regId || l.IdentityProvider.Name == providerName);

                    string? mappingJson = link?.ClaimMappingsJson ?? link?.IdentityProvider?.ClaimMappingsJson;
                    if (!string.IsNullOrWhiteSpace(mappingJson))
                    {
                        var map = JsonSerializer.Deserialize<Dictionary<string, string>>(mappingJson);
                        if (map != null && map.Count > 0)
                        {
                            var newClaims = new List<Claim>();
                            foreach (var kv in map)
                            {
                                var src = kv.Key;
                                var dst = kv.Value;
                                var val = principal.FindFirst(src)?.Value;
                                if (!string.IsNullOrEmpty(val) && !string.IsNullOrEmpty(dst))
                                {
                                    var existing = await _userManager.GetClaimsAsync(user);
                                    if (!existing.Any(c => c.Type == dst && c.Value == val))
                                    {
                                        newClaims.Add(new Claim(dst, val));
                                    }
                                }
                            }
                            if (newClaims.Count > 0)
                            {
                                await _userManager.AddClaimsAsync(user, newClaims);
                            }
                        }
                    }
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed applying claim mappings for client {ClientId} and provider {Provider}", clientId, regId);
        }

        // Eligibility validation BEFORE local sign-in / dynamic cookie
        if (!string.IsNullOrEmpty(clientId))
        {
            try
            {
                var validation = await _realmValidationService.ValidateUserRealmAccessAsync(user, clientId);
                if (!validation.IsValid)
                {
                    _logger.LogWarning("External login denied: user {User} not eligible for client {ClientId}. Reason: {Reason}", user.UserName, clientId, validation.Reason);
                    // Sign out external temp principal to avoid lingering state
                    await HttpContext.SignOutAsync(OpenIddictClientAspNetCoreDefaults.AuthenticationScheme);
                    return Redirect(BuildAccessDeniedUrl(returnUrl, clientId));
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error validating eligibility for user {User} and client {ClientId} during external callback", user.Id, clientId);
                await HttpContext.SignOutAsync(OpenIddictClientAspNetCoreDefaults.AuthenticationScheme);
                return Redirect(BuildAccessDeniedUrl(returnUrl, clientId));
            }
        }

        // Build additional per-session claims to remember external provider for cascade sign-out
        var sessionClaims = new List<Claim>();
        if (!string.IsNullOrWhiteSpace(regId))
        {
            sessionClaims.Add(new Claim("ext_reg_id", regId));
        }

        if (!string.IsNullOrWhiteSpace(providerName))
        {
            sessionClaims.Add(new Claim("ext_provider", providerName));
        }

        if (!string.IsNullOrWhiteSpace(subject))
        {
            sessionClaims.Add(new Claim("ext_sub", subject));
        }

        await _signInManager.SignInWithClaimsAsync(user, isPersistent: false, sessionClaims);

        // Dynamic client cookie only after eligibility validated
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

        // IMPORTANT: Removed automatic user-to-client linking to prevent privilege escalation.
        // Admin must assign users to clients explicitly; validator enforces assignment.

        if (newlyCreated)
        {
            _logger.LogInformation("External user {UserId} created; redirecting to registration success notification", user.Id);
            return RedirectToAction("RegisterSuccess", "Auth");
        }

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
        try
        {
            HttpContext.Session.Remove("ExternalRegistrationId");
        }
        catch { }

        try
        {
            var resume = HttpContext.Session.GetString("ExternalSignoutResumeUrl");
            if (!string.IsNullOrWhiteSpace(resume))
            {
                HttpContext.Session.Remove("ExternalSignoutResumeUrl");
                return Redirect(resume);
            }
        }
        catch { }

        if (!string.IsNullOrEmpty(returnUrl))
        {
            return Redirect(returnUrl);
        }

        return Ok(new { Message = "External sign-out completed" });
    }

    private static string BuildDisplayNameFromEmailOrUserName(string? input)
    {
        if (string.IsNullOrWhiteSpace(input))
        {
            return "New User";
        }

        var source = input;
        if (source.Contains('@'))
        {
            source = source.Split('@')[0];
        }

        var friendly = source.Replace('.', ' ').Replace('_', ' ').Replace('-', ' ');
        var words = friendly.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        return string.Join(' ', words.Select(w => char.ToUpper(w[0]) + w.Substring(1).ToLower()));
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
