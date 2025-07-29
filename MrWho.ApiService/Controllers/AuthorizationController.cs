using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using MrWho.ApiService.Models;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using System.Collections.Immutable;
using System.Security.Claims;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace MrWho.ApiService.Controllers;

[ApiController]
[Route("connect")]
public class AuthorizationController : ControllerBase
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly IOpenIddictApplicationManager _applicationManager;
    private readonly ILogger<AuthorizationController> _logger;

    public AuthorizationController(
        UserManager<ApplicationUser> userManager, 
        SignInManager<ApplicationUser> signInManager,
        IOpenIddictApplicationManager applicationManager,
        ILogger<AuthorizationController> logger)
    {
        _userManager = userManager;
        _signInManager = signInManager;
        _applicationManager = applicationManager;
        _logger = logger;
    }

    [HttpGet("authorize")]
    [HttpPost("authorize")]
    [IgnoreAntiforgeryToken]
    public async Task<IActionResult> Authorize()
    {
        var request = HttpContext.GetOpenIddictServerRequest() ??
            throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

        _logger.LogInformation("=== AUTHORIZE REQUEST ===");
        _logger.LogInformation("Request Method: {Method}", Request.Method);
        _logger.LogInformation("Client ID: {ClientId}", request.ClientId);
        _logger.LogInformation("Response Type: {ResponseType}", request.ResponseType);
        _logger.LogInformation("Scope: {Scope}", request.Scope);
        _logger.LogInformation("Redirect URI: {RedirectUri}", request.RedirectUri);

        // Retrieve the user principal stored in the authentication cookie
        var result = await HttpContext.AuthenticateAsync(IdentityConstants.ApplicationScheme);
        _logger.LogInformation("Authentication result succeeded: {Succeeded}", result.Succeeded);

        // If the user principal can't be extracted or the cookie is too old, redirect to login
        if (!result.Succeeded)
        {
            _logger.LogInformation("User not authenticated, redirecting to login");
            // Redirect to login page
            return Challenge(
                authenticationSchemes: IdentityConstants.ApplicationScheme,
                properties: new AuthenticationProperties
                {
                    RedirectUri = Request.PathBase + Request.Path + QueryString.Create(
                        Request.HasFormContentType ? Request.Form.ToList() : Request.Query.ToList())
                });
        }

        // Retrieve the profile of the logged in user
        var user = await _userManager.GetUserAsync(result.Principal!);
        _logger.LogInformation("User retrieved: {Found}, User ID: {UserId}, Email: {Email}, Active: {Active}", 
            user != null, user?.Id ?? "null", user?.Email ?? "null", user?.IsActive ?? false);
            
        if (user == null)
        {
            _logger.LogError("User details cannot be retrieved from principal");
            throw new InvalidOperationException("The user details cannot be retrieved.");
        }

        if (!user.IsActive)
        {
            _logger.LogWarning("User account is not active: {UserId}", user.Id);
            return Forbid(
                authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                properties: new AuthenticationProperties(new Dictionary<string, string?>
                {
                    [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
                    [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "The user account is not active."
                }));
        }

        // Retrieve the application details from the database
        var application = await _applicationManager.FindByClientIdAsync(request.ClientId!);
        _logger.LogInformation("Application found: {Found}, Client ID: {ClientId}", 
            application != null, request.ClientId);
            
        if (application == null)
        {
            _logger.LogError("Application not found for client ID: {ClientId}", request.ClientId);
            throw new InvalidOperationException("Details concerning the calling client application cannot be found.");
        }

        // Create the claims principal that will be used to create the authorization code/access token
        var scopes = request.GetScopes();
        _logger.LogInformation("Requested scopes: {Scopes}", string.Join(", ", scopes));
        
        var principal = await CreatePrincipalAsync(user, scopes);

        // Set the list of scopes granted to the client application
        principal.SetScopes(scopes);

        _logger.LogInformation("Authorization successful, creating authorization code for user: {UserId}", user.Id);
        _logger.LogInformation("=== AUTHORIZE SUCCESS ===");

        // ? FIX: Check if this is a consent request or direct authorization
        // For direct authorization without consent screen, we need to handle this properly
        var claimsPrincipal = await CreatePrincipalAsync(user, scopes);
        claimsPrincipal.SetScopes(scopes);
        
        // Set additional properties to prevent redirect loop
        claimsPrincipal.SetDestinations(GetDestinations);
        
        _logger.LogInformation("Returning authorization response for user: {UserId}", user.Id);
        
        return SignIn(claimsPrincipal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }

    [HttpPost("token")]
    [IgnoreAntiforgeryToken]
    [Produces("application/json")]
    public async Task<IActionResult> Exchange()
    {
        // ? This method should not be called since EnableTokenEndpointPassthrough is disabled
        // OpenIddict handles token exchange automatically
        _logger.LogWarning("Exchange method called but token endpoint passthrough is disabled");
        
        // Return a 404 since this endpoint should not be handling requests manually
        return NotFound("Token endpoint is handled automatically by OpenIddict");
    }

    [HttpGet("logout")]
    [HttpPost("logout")]
    [IgnoreAntiforgeryToken]
    public async Task<IActionResult> Logout()
    {
        var request = HttpContext.GetOpenIddictServerRequest() ??
            throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

        await _signInManager.SignOutAsync();

        // Returning a SignOutResult will ask OpenIddict to redirect the user agent
        // to the post_logout_redirect_uri specified by the client application or to
        // the RedirectUri specified in the authentication properties
        return SignOut(
            authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
            properties: new AuthenticationProperties
            {
                RedirectUri = request.PostLogoutRedirectUri
            });
    }

    [HttpGet("userinfo")]
    [HttpPost("userinfo")]
    [IgnoreAntiforgeryToken]
    [Authorize(AuthenticationSchemes = OpenIddictServerAspNetCoreDefaults.AuthenticationScheme)]
    [Produces("application/json")]
    public async Task<IActionResult> Userinfo()
    {
        var user = await _userManager.FindByIdAsync(User.GetClaim(Claims.Subject)!);
        if (user == null)
        {
            return BadRequest(new
            {
                error = "invalid_token",
                error_description = "The specified access token is invalid."
            });
        }

        var claims = new Dictionary<string, object>(StringComparer.Ordinal)
        {
            [Claims.Subject] = user.Id
        };

        if (User.HasScope(Scopes.Email))
        {
            claims[Claims.Email] = user.Email!;
            claims[Claims.EmailVerified] = user.EmailConfirmed;
        }

        if (User.HasScope(Scopes.Profile))
        {
            if (!string.IsNullOrEmpty(user.FirstName))
                claims[Claims.GivenName] = user.FirstName;
            
            if (!string.IsNullOrEmpty(user.LastName))
                claims[Claims.FamilyName] = user.LastName;

            var fullName = $"{user.FirstName} {user.LastName}".Trim();
            if (!string.IsNullOrEmpty(fullName))
                claims[Claims.Name] = fullName;

            claims[Claims.PreferredUsername] = user.UserName!;
        }

        if (User.HasScope(Scopes.Roles))
        {
            claims[Claims.Role] = "user";
        }

        return Ok(claims);
    }

    private async Task<ClaimsPrincipal> CreatePrincipalAsync(ApplicationUser user, ImmutableArray<string> scopes)
    {
        var identity = new ClaimsIdentity(
            TokenValidationParameters.DefaultAuthenticationType,
            Claims.Name,
            Claims.Role);

        identity.AddClaim(new Claim(Claims.Subject, user.Id));
        identity.AddClaim(new Claim(Claims.PreferredUsername, user.UserName!));

        if (scopes.Contains(Scopes.Email))
        {
            identity.AddClaim(new Claim(Claims.Email, user.Email!));
            identity.AddClaim(new Claim(Claims.EmailVerified, user.EmailConfirmed.ToString().ToLower()));
        }

        if (scopes.Contains(Scopes.Profile))
        {
            if (!string.IsNullOrEmpty(user.FirstName))
                identity.AddClaim(new Claim(Claims.GivenName, user.FirstName));
            
            if (!string.IsNullOrEmpty(user.LastName))
                identity.AddClaim(new Claim(Claims.FamilyName, user.LastName));

            var fullName = $"{user.FirstName} {user.LastName}".Trim();
            if (!string.IsNullOrEmpty(fullName))
                identity.AddClaim(new Claim(Claims.Name, fullName));
        }

        if (scopes.Contains(Scopes.Roles))
        {
            identity.AddClaim(new Claim(Claims.Role, "user"));
        }

        var principal = new ClaimsPrincipal(identity);
        principal.SetScopes(scopes);

        return principal;
    }
}