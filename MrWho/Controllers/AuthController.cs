using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using MrWho.Services;
using System.Security.Claims;
using System.Web;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace MrWho.Controllers;

[Route("connect")]
public class AuthController : Controller
{
    private readonly SignInManager<IdentityUser> _signInManager;
    private readonly UserManager<IdentityUser> _userManager;
    private readonly IClientCookieConfigurationService _cookieService;
    private readonly IDynamicCookieService _dynamicCookieService;
    private readonly ILogger<AuthController> _logger;

    public AuthController(
        SignInManager<IdentityUser> signInManager, 
        UserManager<IdentityUser> userManager,
        IClientCookieConfigurationService cookieService,
        IDynamicCookieService dynamicCookieService,
        ILogger<AuthController> logger)
    {
        _signInManager = signInManager;
        _userManager = userManager;
        _cookieService = cookieService;
        _dynamicCookieService = dynamicCookieService;
        _logger = logger;
    }

    // REMOVED: [HttpGet("authorize")] - Now handled by minimal API with client-specific cookies

    [HttpGet("login")]
    public IActionResult Login(string? returnUrl = null, string? clientId = null)
    {
        _logger.LogDebug("Login page requested, returnUrl = {ReturnUrl}, clientId = {ClientId}", returnUrl, clientId);
        ViewData["ReturnUrl"] = returnUrl;
        ViewData["ClientId"] = clientId;
        return View(new LoginViewModel());
    }

    [HttpPost("login")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Login(LoginViewModel model, string? returnUrl = null, string? clientId = null)
    {
        ViewData["ReturnUrl"] = returnUrl;
        ViewData["ClientId"] = clientId;
        _logger.LogDebug("Login POST: Email={Email}, ReturnUrl={ReturnUrl}, ClientId={ClientId}", 
            model.Email, returnUrl, clientId);

        if (ModelState.IsValid)
        {
            var result = await _signInManager.PasswordSignInAsync(model.Email, model.Password, model.RememberMe, lockoutOnFailure: false);
            _logger.LogDebug("Login attempt result: Success={Success}", result.Succeeded);
            
            if (result.Succeeded)
            {
                var user = await _userManager.FindByNameAsync(model.Email);
                if (user == null)
                {
                    _logger.LogError("User not found after successful login: {Email}", model.Email);
                    ModelState.AddModelError(string.Empty, "Authentication error occurred.");
                    return View(model);
                }

                // If we have a client ID, sign in with client-specific cookie using the dynamic service
                if (!string.IsNullOrEmpty(clientId))
                {
                    try
                    {
                        await _dynamicCookieService.SignInWithClientCookieAsync(clientId, user, model.RememberMe);
                        _logger.LogDebug("Signed in user {UserName} with client-specific cookie for client {ClientId}", 
                            user.UserName, clientId);
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning(ex, "Failed to sign in with client-specific cookie for client {ClientId}", clientId);
                        // Continue anyway - the default SignInManager login above should still work
                    }
                }

                // CRITICAL FIX: For OIDC flows, redirect back to the authorization endpoint
                // to complete the authorization flow properly
                if (!string.IsNullOrEmpty(returnUrl))
                {
                    // Check if this is an OIDC authorization request
                    if (returnUrl.Contains("/connect/authorize"))
                    {
                        _logger.LogDebug("Login successful, redirecting to OIDC authorization endpoint: {ReturnUrl}", returnUrl);
                        return Redirect(returnUrl);
                    }
                    else if (Url.IsLocalUrl(returnUrl))
                    {
                        _logger.LogDebug("Login successful, redirecting to local URL: {ReturnUrl}", returnUrl);
                        return Redirect(returnUrl);
                    }
                }
                
                _logger.LogDebug("Login successful, redirecting to Home");
                return RedirectToAction("Index", "Home");
            }
            else
            {
                _logger.LogDebug("Login failed: {Result}", result);
                ModelState.AddModelError(string.Empty, "Invalid login attempt.");
            }
        }
        else
        {
            _logger.LogDebug("Login ModelState invalid");
        }

        return View(model);
    }

    [HttpGet("logout")]
    public async Task<IActionResult> Logout(string? clientId = null)
    {
        var request = HttpContext.GetOpenIddictServerRequest();
        
        // Try to get clientId from multiple sources
        string? detectedClientId = clientId ?? await TryGetClientIdFromRequest();
        
        _logger.LogDebug("Logout requested. ClientId parameter: {ClientId}, Detected ClientId: {DetectedClientId}", 
            clientId, detectedClientId);

        // CRITICAL FIX: Sign out from all possible authentication schemes
        await SignOutFromAllSchemesAsync(detectedClientId);
        
        if (request != null)
        {
            // This is an OIDC logout request
            _logger.LogDebug("Processing OIDC logout request with post_logout_redirect_uri: {PostLogoutRedirectUri}", 
                request.PostLogoutRedirectUri);
            
            // Return a SignOut result to complete the OIDC logout flow
            return SignOut(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        // Regular logout
        _logger.LogDebug("Processing regular logout, redirecting to Home");
        return RedirectToAction("Index", "Home");
    }

    [HttpPost("logout")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> LogoutPost(string? clientId = null)
    {
        // Try to get clientId from multiple sources
        string? detectedClientId = clientId ?? await TryGetClientIdFromRequest();
        
        _logger.LogDebug("Logout POST requested. ClientId parameter: {ClientId}, Detected ClientId: {DetectedClientId}", 
            clientId, detectedClientId);

        // CRITICAL FIX: Sign out from all possible authentication schemes
        await SignOutFromAllSchemesAsync(detectedClientId);

        return RedirectToAction("Index", "Home");
    }

    /// <summary>
    /// Attempts to detect the client ID from the current request
    /// </summary>
    private async Task<string?> TryGetClientIdFromRequest()
    {
        try
        {
            // First try to get it from the OIDC request context
            var request = HttpContext.GetOpenIddictServerRequest();
            if (!string.IsNullOrEmpty(request?.ClientId))
            {
                _logger.LogDebug("Found ClientId in OpenIddict request: {ClientId}", request.ClientId);
                return request.ClientId;
            }

            // Try to get it from query parameters
            if (HttpContext.Request.Query.TryGetValue("client_id", out var clientIdFromQuery))
            {
                _logger.LogDebug("Found ClientId in query parameters: {ClientId}", clientIdFromQuery.ToString());
                return clientIdFromQuery.ToString();
            }

            // Try to use the client cookie service
            var clientIdFromCookies = await _cookieService.GetClientIdFromRequestAsync(HttpContext);
            if (!string.IsNullOrEmpty(clientIdFromCookies))
            {
                _logger.LogDebug("Found ClientId from cookie analysis: {ClientId}", clientIdFromCookies);
                return clientIdFromCookies;
            }

            // Try to get it from the referring URL (if coming from authorization flow)
            var referer = HttpContext.Request.Headers.Referer.ToString();
            if (!string.IsNullOrEmpty(referer) && referer.Contains("client_id="))
            {
                var uri = new Uri(referer);
                var query = HttpUtility.ParseQueryString(uri.Query);
                var clientIdFromReferer = query["client_id"];
                if (!string.IsNullOrEmpty(clientIdFromReferer))
                {
                    _logger.LogDebug("Found ClientId in referer URL: {ClientId}", clientIdFromReferer);
                    return clientIdFromReferer;
                }
            }

            _logger.LogDebug("Could not detect ClientId from request");
            return null;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Error attempting to detect ClientId from request");
            return null;
        }
    }

    /// <summary>
    /// Signs out from all relevant authentication schemes
    /// </summary>
    private async Task SignOutFromAllSchemesAsync(string? clientId)
    {
        try
        {
            // Always sign out from the default Identity scheme
            await _signInManager.SignOutAsync();
            _logger.LogDebug("Signed out from default Identity scheme");

            // If we have a client ID, also sign out from the client-specific cookie
            if (!string.IsNullOrEmpty(clientId))
            {
                try
                {
                    await _dynamicCookieService.SignOutFromClientAsync(clientId);
                    _logger.LogDebug("Signed out from client-specific cookie for client {ClientId}", clientId);
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Failed to sign out from client-specific cookie for client {ClientId}", clientId);
                }
            }
            else
            {
                // If we don't know the specific client, try to sign out from all configured client schemes
                _logger.LogDebug("No specific client ID available, attempting to sign out from all client configurations");
                var allConfigurations = _cookieService.GetAllClientConfigurations();
                
                foreach (var config in allConfigurations)
                {
                    try
                    {
                        await _dynamicCookieService.SignOutFromClientAsync(config.Key);
                        _logger.LogDebug("Signed out from client configuration for client {ClientId}", config.Key);
                    }
                    catch (Exception ex)
                    {
                        _logger.LogDebug(ex, "Failed to sign out from client configuration for client {ClientId} (may not be signed in)", config.Key);
                    }
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during logout process");
        }
    }

    /// <summary>
    /// Get user's display name with fallback logic
    /// </summary>
    private async Task<string> GetUserDisplayNameAsync(IdentityUser user)
    {
        try
        {
            var claims = await _userManager.GetClaimsAsync(user);
            var nameClaim = claims.FirstOrDefault(c => c.Type == "name")?.Value;
            
            if (!string.IsNullOrEmpty(nameClaim))
            {
                return nameClaim;
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error retrieving name claim for user {UserId}", user.Id);
        }

        // Fallback to converting username to friendly display name
        return ConvertToFriendlyName(user.UserName ?? "Unknown User");
    }

    /// <summary>
    /// Add user claims to the identity
    /// </summary>
    private async Task AddUserClaimsToIdentity(ClaimsIdentity identity, IdentityUser user)
    {
        try
        {
            var claims = await _userManager.GetClaimsAsync(user);
            
            // Add profile claims
            var givenName = claims.FirstOrDefault(c => c.Type == "given_name")?.Value;
            if (!string.IsNullOrEmpty(givenName))
            {
                identity.AddClaim(Claims.GivenName, givenName);
            }

            var familyName = claims.FirstOrDefault(c => c.Type == "family_name")?.Value;
            if (!string.IsNullOrEmpty(familyName))
            {
                identity.AddClaim(Claims.FamilyName, familyName);
            }

            var preferredUsername = claims.FirstOrDefault(c => c.Type == "preferred_username")?.Value;
            if (!string.IsNullOrEmpty(preferredUsername))
            {
                identity.AddClaim(Claims.PreferredUsername, preferredUsername);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error adding user claims to identity for user {UserId}", user.Id);
        }
    }

    /// <summary>
    /// Convert a username to a friendly display name
    /// </summary>
    private string ConvertToFriendlyName(string input)
    {
        if (string.IsNullOrEmpty(input))
            return "Unknown User";

        // If username is an email, extract the local part and convert to friendly name
        if (input.Contains('@'))
        {
            var localPart = input.Split('@')[0];
            return ConvertToDisplayName(localPart);
        }

        // Otherwise just convert the username to friendly name
        return ConvertToDisplayName(input);
    }

    /// <summary>
    /// Convert a username or email local part to a friendly display name
    /// </summary>
    private string ConvertToDisplayName(string input)
    {
        if (string.IsNullOrEmpty(input))
            return "Unknown User";

        // Replace common separators with spaces
        var friendlyName = input.Replace('.', ' ')
                               .Replace('_', ' ')
                               .Replace('-', ' ');

        // Split into words and capitalize each word
        var words = friendlyName.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        var capitalizedWords = words.Select(word => 
            word.Length > 0 ? char.ToUpper(word[0]) + word.Substring(1).ToLower() : word);

        return string.Join(" ", capitalizedWords);
    }

    [HttpGet("access-denied")]
    public IActionResult AccessDenied(string? returnUrl = null)
    {
        _logger.LogDebug("Access denied page requested, returnUrl = {ReturnUrl}", returnUrl);
        ViewData["ReturnUrl"] = returnUrl;
        return View();
    }
}

public class LoginViewModel
{
    public string Email { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;
    public bool RememberMe { get; set; }
}