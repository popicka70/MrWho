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
using MrWho.Shared.Models;
using MrWho.Data;
using MrWho.Models;

namespace MrWho.Controllers;

[Route("connect")]
public class AuthController : Controller
{
    private readonly SignInManager<IdentityUser> _signInManager;
    private readonly UserManager<IdentityUser> _userManager;
    private readonly IClientCookieConfigurationService _cookieService;
    private readonly IDynamicCookieService _dynamicCookieService;
    private readonly IOpenIddictApplicationManager _applicationManager;
    private readonly ApplicationDbContext _db;
    private readonly ILogger<AuthController> _logger;

    public AuthController(
        SignInManager<IdentityUser> signInManager, 
        UserManager<IdentityUser> userManager,
        IClientCookieConfigurationService cookieService,
        IDynamicCookieService dynamicCookieService,
        IOpenIddictApplicationManager applicationManager,
        ApplicationDbContext db,
        ILogger<AuthController> logger)
    {
        _signInManager = signInManager;
        _userManager = userManager;
        _cookieService = cookieService;
        _dynamicCookieService = dynamicCookieService;
        _applicationManager = applicationManager;
        _db = db;
        _logger = logger;
    }

    // REMOVED: [HttpGet("authorize")] - Now handled by minimal API with client-specific cookies

    [HttpGet("login")]
    public async Task<IActionResult> Login(string? returnUrl = null, string? clientId = null, string? mode = null)
    {
        _logger.LogDebug("Login page requested, returnUrl = {ReturnUrl}, clientId = {ClientId}", returnUrl, clientId);

        // If clientId is not provided explicitly, try to extract it from the returnUrl's client_id parameter
        if (string.IsNullOrEmpty(clientId) && !string.IsNullOrEmpty(returnUrl))
        {
            var extracted = TryExtractClientIdFromReturnUrl(returnUrl);
            if (!string.IsNullOrEmpty(extracted))
            {
                clientId = extracted;
                _logger.LogDebug("Extracted client_id '{ClientId}' from returnUrl", clientId);
            }
        }

        ViewData["ReturnUrl"] = returnUrl;
        ViewData["ClientId"] = clientId;

        // Try to get client name if clientId is provided
        string? clientName = null;
        if (!string.IsNullOrEmpty(clientId))
        {
            try
            {
                var application = await _applicationManager.FindByClientIdAsync(clientId);
                if (application != null)
                {
                    clientName = await _applicationManager.GetDisplayNameAsync(application);
                    if (string.IsNullOrEmpty(clientName))
                    {
                        clientName = clientId; // Fallback to client ID if no display name
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to retrieve client information for clientId: {ClientId}", clientId);
            }
        }

        ViewData["ClientName"] = clientName;
        var useCode = string.Equals(mode, "code", StringComparison.OrdinalIgnoreCase);
        return View(new LoginViewModel { UseCode = useCode });
    }

    [HttpPost("login")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Login(LoginViewModel model, string? returnUrl = null, string? clientId = null)
    {
        // If clientId not explicitly passed, attempt extraction from returnUrl
        if (string.IsNullOrEmpty(clientId) && !string.IsNullOrEmpty(returnUrl))
        {
            var extracted = TryExtractClientIdFromReturnUrl(returnUrl);
            if (!string.IsNullOrEmpty(extracted))
            {
                clientId = extracted;
                _logger.LogDebug("POST login: extracted client_id '{ClientId}' from returnUrl", clientId);
            }
        }

        ViewData["ReturnUrl"] = returnUrl;
        ViewData["ClientId"] = clientId;

        // Try to get client name if clientId is provided (for error scenarios)
        string? clientName = null;
        if (!string.IsNullOrEmpty(clientId))
        {
            try
            {
                var application = await _applicationManager.FindByClientIdAsync(clientId);
                if (application != null)
                {
                    clientName = await _applicationManager.GetDisplayNameAsync(application);
                    if (string.IsNullOrEmpty(clientName))
                    {
                        clientName = clientId; // Fallback to client ID if no display name
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to retrieve client information for clientId: {ClientId}", clientId);
            }
        }

        ViewData["ClientName"] = clientName;
        _logger.LogDebug("Login POST: Email={Email}, ReturnUrl={ReturnUrl}, ClientId={ClientId}", 
            model.Email, returnUrl, clientId);

        if (ModelState.IsValid)
        {
            // Passwordless/code-only branch
            if (model.UseCode)
            {
                if (string.IsNullOrWhiteSpace(model.Email) || string.IsNullOrWhiteSpace(model.Code))
                {
                    ModelState.AddModelError(string.Empty, "Email and code are required.");
                    return View(model);
                }

                var user = await _userManager.FindByNameAsync(model.Email) ?? await _userManager.FindByEmailAsync(model.Email);
                if (user == null)
                {
                    _logger.LogDebug("Code-only login failed: user not found for {Email}", model.Email);
                    ModelState.AddModelError(string.Empty, "Invalid login attempt.");
                    return View(model);
                }

                if (!await _userManager.GetTwoFactorEnabledAsync(user))
                {
                    _logger.LogDebug("Code-only login not permitted: 2FA disabled for {Email}", model.Email);
                    ModelState.AddModelError(string.Empty, "This account does not allow code-only sign in.");
                    return View(model);
                }

                var code = model.Code.Replace(" ", string.Empty).Replace("-", string.Empty);
                var isValid = await _userManager.VerifyTwoFactorTokenAsync(user, _userManager.Options.Tokens.AuthenticatorTokenProvider, code);
                if (!isValid)
                {
                    _logger.LogDebug("Code-only login failed: invalid code for {Email}", model.Email);
                    ModelState.AddModelError(string.Empty, "Invalid code.");
                    return View(model);
                }

                // Successful code-only auth: sign in with MFA method so AMR propagates
                await _signInManager.SignInAsync(user, isPersistent: model.RememberMe, authenticationMethod: "mfa");

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
                    }
                }

                if (!string.IsNullOrEmpty(returnUrl))
                {
                    if (returnUrl.Contains("/connect/authorize"))
                    {
                        _logger.LogDebug("Code-only login successful, redirecting to OIDC authorization endpoint: {ReturnUrl}", returnUrl);
                        return Redirect(returnUrl);
                    }
                    else if (Url.IsLocalUrl(returnUrl))
                    {
                        _logger.LogDebug("Code-only login successful, redirecting to local URL: {ReturnUrl}", returnUrl);
                        return Redirect(returnUrl);
                    }
                }

                _logger.LogDebug("Code-only login successful, redirecting to Home");
                return RedirectToAction("Index", "Home");
            }

            var result = await _signInManager.PasswordSignInAsync(model.Email, model.Password, model.RememberMe, lockoutOnFailure: false);
            _logger.LogDebug("Login attempt result: Success={Success}, Requires2FA={RequiresTwoFactor}", result.Succeeded, result.RequiresTwoFactor);
            
            if (result.RequiresTwoFactor)
            {
                var redirect = "/mfa/challenge" +
                                (!string.IsNullOrEmpty(returnUrl) ? ($"?returnUrl={Uri.EscapeDataString(returnUrl)}") : string.Empty) +
                                (model.RememberMe ? (string.IsNullOrEmpty(returnUrl) ? "?" : "&") + "RememberMe=true" : string.Empty);
                _logger.LogDebug("Login requires 2FA, redirecting to {Redirect}", redirect);
                return Redirect(redirect);
            }
            else if (result.Succeeded)
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
    public async Task<IActionResult> Logout(string? clientId = null, string? post_logout_redirect_uri = null)
    {
        _logger.LogInformation("GET /connect/logout accessed directly. ClientId: {ClientId}, PostLogoutUri: {PostLogoutUri}", clientId, post_logout_redirect_uri);
        
        var request = HttpContext.GetOpenIddictServerRequest();
        
        // Check if this is a proper OIDC logout request by verifying OIDC-specific parameters
        bool isOidcLogoutRequest = request != null && (
            !string.IsNullOrEmpty(request.IdTokenHint) || 
            !string.IsNullOrEmpty(request.PostLogoutRedirectUri) ||
            !string.IsNullOrEmpty(request.ClientId) ||
            !string.IsNullOrEmpty(request.State)
        );
        
        if (isOidcLogoutRequest)
        {
            _logger.LogInformation("OIDC logout request detected with proper parameters, processing normally");
            return await ProcessLogout(clientId, post_logout_redirect_uri);
        }
        
        // For direct browser access without OIDC parameters, perform logout and redirect to home
        _logger.LogInformation("Direct browser logout access detected (no OIDC parameters)");
        
        // Perform logout
        await _signInManager.SignOutAsync();
        
        // Clear any client-specific cookies if we can detect the client
        string? detectedClientId = clientId ?? await TryGetClientIdFromRequest();
        if (!string.IsNullOrEmpty(detectedClientId))
        {
            try
            {
                await _dynamicCookieService.SignOutFromClientAsync(detectedClientId);
                _logger.LogDebug("Signed out from client-specific cookie for client {ClientId}", detectedClientId);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to sign out from client-specific cookie for client {ClientId}", detectedClientId);
            }
        }
        
        // Redirect to home with success message
        return RedirectToAction("Index", "Home", new { logout = "success" });
    }

    [HttpPost("logout")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> LogoutPost(string? clientId = null, string? post_logout_redirect_uri = null)
    {
        _logger.LogInformation("POST /connect/logout accessed. ClientId: {ClientId}, PostLogoutUri: {PostLogoutUri}", clientId, post_logout_redirect_uri);
        
        var request = HttpContext.GetOpenIddictServerRequest();
        
        // Check if this is a proper OIDC logout request by verifying OIDC-specific parameters
        bool isOidcLogoutRequest = request != null && (
            !string.IsNullOrEmpty(request.IdTokenHint) || 
            !string.IsNullOrEmpty(request.PostLogoutRedirectUri) ||
            !string.IsNullOrEmpty(request.ClientId) ||
            !string.IsNullOrEmpty(request.State)
        );
        
        if (isOidcLogoutRequest)
        {
            _logger.LogInformation("OIDC logout request detected with proper parameters, processing normally");
            return await ProcessLogout(clientId, post_logout_redirect_uri);
        }
        
        // For regular UI POST requests (like from our logout buttons)
        _logger.LogInformation("UI logout POST request detected (no OIDC parameters)");
        
        // Perform logout
        await _signInManager.SignOutAsync();
        
        // Clear any client-specific cookies if we can detect the client
        string? detectedClientId = clientId ?? await TryGetClientIdFromRequest();
        if (!string.IsNullOrEmpty(detectedClientId))
        {
            try
            {
                await _dynamicCookieService.SignOutFromClientAsync(detectedClientId);
                _logger.LogDebug("Signed out from client-specific cookie for client {ClientId}", detectedClientId);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to sign out from client-specific cookie for client {ClientId}", detectedClientId);
            }
        }
        
        // Redirect to home with success message
        return RedirectToAction("Index", "Home", new { logout = "success" });
    }

    private async Task<IActionResult> ProcessLogout(string? clientId, string? post_logout_redirect_uri)
    {
        var request = HttpContext.GetOpenIddictServerRequest();
        
        // Try to get clientId from multiple sources
        string? detectedClientId = clientId ?? await TryGetClientIdFromRequest();
        
        _logger.LogDebug("Processing OIDC logout. Method: {Method}, ClientId parameter: {ClientId}, Detected ClientId: {DetectedClientId}, Post logout URI: {PostLogoutUri}", 
            HttpContext.Request.Method, clientId, detectedClientId, post_logout_redirect_uri ?? request?.PostLogoutRedirectUri);

        // CRITICAL FIX: Sign out from all possible authentication schemes
        await SignOutFromAllSchemesAsync(detectedClientId);
        
        // This should only be called for OIDC logout requests now
        if (request != null)
        {
            _logger.LogDebug("Processing OIDC logout request with post_logout_redirect_uri: {PostLogoutRedirectUri}", 
                request.PostLogoutRedirectUri);
            
            // Return a SignOut result to complete the OIDC logout flow
            return SignOut(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }
        
        // Fallback - this shouldn't happen anymore since UI requests now redirect directly
        _logger.LogWarning("ProcessLogout called without OIDC request - redirecting to home");
        return RedirectToAction("Index", "Home", new { logout = "success" });
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

    // Helper: extract client_id from a full OIDC returnUrl (absolute or relative)
    private static string? TryExtractClientIdFromReturnUrl(string? returnUrl)
    {
        if (string.IsNullOrEmpty(returnUrl)) return null;
        try
        {
            // Handle both absolute and relative URLs safely
            if (Uri.TryCreate(returnUrl, UriKind.Absolute, out var absUri))
            {
                var query = HttpUtility.ParseQueryString(absUri.Query);
                return query["client_id"];            
            }
            else
            {
                var idx = returnUrl.IndexOf('?');
                if (idx >= 0 && idx < returnUrl.Length - 1)
                {
                    var query = HttpUtility.ParseQueryString(returnUrl.Substring(idx)); // includes leading '?'
                    return query["client_id"];            
                }
            }
        }
        catch
        {
            // Ignore
        }
        return null;
    }

    [HttpGet("access-denied")]
    public async Task<IActionResult> AccessDenied(string? returnUrl = null, string? clientId = null)
    {
        _logger.LogDebug("Access denied page requested, returnUrl = {ReturnUrl}, clientId = {ClientId}", returnUrl, clientId);
        ViewData["ReturnUrl"] = returnUrl;
        ViewData["ClientId"] = clientId;

        // Try to get client ID from query parameters if not provided directly
        if (string.IsNullOrEmpty(clientId) && !string.IsNullOrEmpty(returnUrl))
        {
            try
            {
                // Handle both absolute and relative URLs safely
                if (Uri.TryCreate(returnUrl, UriKind.Absolute, out var absUri))
                {
                    var query = HttpUtility.ParseQueryString(absUri.Query);
                    clientId = query["client_id"];
                }
                else if (Uri.TryCreate(returnUrl, UriKind.Relative, out var relUri))
                {
                    // relUri.Query is empty for relative URIs created without base; parse manually
                    var idx = returnUrl.IndexOf('?');
                    if (idx >= 0 && idx < returnUrl.Length - 1)
                    {
                        var query = HttpUtility.ParseQueryString(returnUrl.Substring(idx)); // includes leading '?'
                        clientId = query["client_id"];
                    }
                }

                ViewData["ClientId"] = clientId;
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Failed to extract client_id from returnUrl: {ReturnUrl}", returnUrl);
            }
        }

        // Try to get client name if clientId is available
        string? clientName = null;
        if (!string.IsNullOrEmpty(clientId))
        {
            try
            {
                var application = await _applicationManager.FindByClientIdAsync(clientId);
                if (application != null)
                {
                    clientName = await _applicationManager.GetDisplayNameAsync(application);
                    if (string.IsNullOrEmpty(clientName))
                    {
                        clientName = clientId; // Fallback to client ID if no display name
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to retrieve client information for clientId: {ClientId}", clientId);
            }
        }

        ViewData["ClientName"] = clientName;
        return View();
    }

    [HttpGet("register")]
    [AllowAnonymous]
    public IActionResult Register()
    {
        return View("Register", new RegisterUserRequest());
    }

    [HttpPost("register")]
    [AllowAnonymous]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Register([FromForm] RegisterUserRequest input)
    {
        if (!ModelState.IsValid)
        {
            return View("Register", input);
        }

        // Check uniqueness
        var existingByEmail = await _userManager.FindByEmailAsync(input.Email);
        if (existingByEmail != null)
        {
            ModelState.AddModelError("Email", "An account with this email already exists.");
            return View("Register", input);
        }

        // Use email as username for now
        var user = new IdentityUser
        {
            UserName = input.Email,
            Email = input.Email,
            EmailConfirmed = false
        };

        var result = await _userManager.CreateAsync(user, input.Password);
        if (!result.Succeeded)
        {
            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }
            return View("Register", input);
        }

        // Create profile with state New
        var profile = new UserProfile
        {
            UserId = user.Id,
            FirstName = input.FirstName,
            LastName = input.LastName,
            DisplayName = $"{input.FirstName} {input.LastName}".Trim(),
            State = UserState.New,
            CreatedAt = DateTime.UtcNow
        };
        _db.UserProfiles.Add(profile);
        await _db.SaveChangesAsync();

        TempData["RegistrationSuccess"] = true;
        return RedirectToAction("RegisterSuccess");
    }

    [HttpGet("register/success")]
    [AllowAnonymous]
    public IActionResult RegisterSuccess()
    {
        return View("RegisterSuccess");
    }
}

public class LoginViewModel
{
    public string Email { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;
    public bool RememberMe { get; set; }
    public bool UseCode { get; set; }
    public string? Code { get; set; }
}