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

        return SignIn(principal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }

    [HttpPost("token")]
    [IgnoreAntiforgeryToken]
    [Produces("application/json")]
    public async Task<IActionResult> Exchange()
    {
        var request = HttpContext.GetOpenIddictServerRequest() ??
            throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

        _logger.LogInformation("=== EXCHANGE TOKEN REQUEST ===");
        _logger.LogInformation("Grant Type: {GrantType}", request.GrantType);
        _logger.LogInformation("Client ID: {ClientId}", request.ClientId);
        _logger.LogInformation("Request Method: {Method}", Request.Method);
        _logger.LogInformation("Request Path: {Path}", Request.Path);

        if (request.IsAuthorizationCodeGrantType())
        {
            _logger.LogInformation("Processing Authorization Code Grant Type");
            
            try
            {
                // Retrieve the claims principal stored in the authorization code
                var authResult = await HttpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
                _logger.LogInformation("Authentication result succeeded: {Succeeded}", authResult.Succeeded);
                
                if (!authResult.Succeeded)
                {
                    _logger.LogError("Failed to authenticate with OpenIddict scheme");
                    return Forbid(
                        authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                        properties: new AuthenticationProperties(new Dictionary<string, string?>
                        {
                            [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
                            [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "The authorization code is invalid or expired."
                        }));
                }
                
                var principal = authResult.Principal!;
                var subjectClaim = principal.GetClaim(Claims.Subject);
                _logger.LogInformation("Subject claim from principal: {Subject}", subjectClaim ?? "null");
                
                if (string.IsNullOrEmpty(subjectClaim))
                {
                    _logger.LogError("No subject claim found in principal");
                    return Forbid(
                        authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                        properties: new AuthenticationProperties(new Dictionary<string, string?>
                        {
                            [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
                            [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "The authorization code does not contain a valid subject claim."
                        }));
                }

                // Retrieve the user profile corresponding to the authorization code
                var user = await _userManager.FindByIdAsync(subjectClaim);
                _logger.LogInformation("User found: {Found}, User ID: {UserId}, Active: {Active}", 
                    user != null, user?.Id ?? "null", user?.IsActive ?? false);
                
                if (user == null)
                {
                    _logger.LogError("User not found for subject: {Subject}", subjectClaim);
                    return Forbid(
                        authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                        properties: new AuthenticationProperties(new Dictionary<string, string?>
                        {
                            [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
                            [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "The token is no longer valid."
                        }));
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

                // Create a new principal containing the updated claims
                var scopes = principal.GetScopes();
                _logger.LogInformation("Scopes from principal: {Scopes}", string.Join(", ", scopes));
                
                var newPrincipal = await CreatePrincipalAsync(user, scopes);
                newPrincipal.SetScopes(scopes);

                _logger.LogInformation("Successfully created new principal for user: {UserId}", user.Id);
                _logger.LogInformation("=== EXCHANGE TOKEN SUCCESS ===");
                
                return SignIn(newPrincipal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Exception during authorization code exchange");
                return Forbid(
                    authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                    properties: new AuthenticationProperties(new Dictionary<string, string?>
                    {
                        [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.ServerError,
                        [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "An error occurred while processing the token request."
                    }));
            }
        }

        if (request.IsPasswordGrantType())
        {
            _logger.LogInformation("Processing Password Grant Type for username: {Username}", request.Username);
            
            var user = await _userManager.FindByEmailAsync(request.Username!) ??
                       await _userManager.FindByNameAsync(request.Username!);

            if (user == null || !user.IsActive)
            {
                _logger.LogWarning("Password grant failed: User not found or not active for username: {Username}", request.Username);
                var properties = new AuthenticationProperties(new Dictionary<string, string?>
                {
                    [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
                    [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] =
                        "The username/password couple is invalid."
                });

                return Forbid(properties, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
            }

            var result = await _signInManager.CheckPasswordSignInAsync(user, request.Password!, lockoutOnFailure: false);
            if (!result.Succeeded)
            {
                _logger.LogWarning("Password grant failed: Invalid password for username: {Username}", request.Username);
                var properties = new AuthenticationProperties(new Dictionary<string, string?>
                {
                    [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
                    [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] =
                        "The username/password couple is invalid."
                });

                return Forbid(properties, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
            }

            var principal = await CreatePrincipalAsync(user, request.GetScopes());
            _logger.LogInformation("Password grant successful for user: {UserId}", user.Id);
            return SignIn(principal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        if (request.IsClientCredentialsGrantType())
        {
            _logger.LogInformation("Processing Client Credentials Grant Type");
            
            var application = await _applicationManager.FindByClientIdAsync(request.ClientId!);
            if (application == null)
            {
                _logger.LogError("Client credentials grant failed: Application not found for client ID: {ClientId}", request.ClientId);
                throw new InvalidOperationException("The application details cannot be found in the database.");
            }

            var identity = new ClaimsIdentity(
                TokenValidationParameters.DefaultAuthenticationType,
                Claims.Name,
                Claims.Role);

            var clientId = await _applicationManager.GetClientIdAsync(application);
            var displayName = await _applicationManager.GetDisplayNameAsync(application) ?? "Unknown";

            identity.AddClaim(new Claim(Claims.Subject, clientId!));
            identity.AddClaim(new Claim(Claims.Name, displayName));

            var principal = new ClaimsPrincipal(identity);
            principal.SetScopes(request.GetScopes());

            _logger.LogInformation("Client credentials grant successful for client: {ClientId}", clientId);
            return SignIn(principal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        if (request.IsRefreshTokenGrantType())
        {
            _logger.LogInformation("Processing Refresh Token Grant Type");
            
            // Retrieve the claims principal stored in the refresh token
            var principal = (await HttpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme)).Principal!;

            // Retrieve the user profile corresponding to the refresh token
            var user = await _userManager.FindByIdAsync(principal.GetClaim(Claims.Subject)!);
            if (user == null)
            {
                _logger.LogWarning("Refresh token grant failed: User not found");
                return Forbid(
                    authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                    properties: new AuthenticationProperties(new Dictionary<string, string?>
                    {
                        [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
                        [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "The refresh token is no longer valid."
                    }));
            }

            if (!user.IsActive)
            {
                _logger.LogWarning("Refresh token grant failed: User account not active: {UserId}", user.Id);
                return Forbid(
                    authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                    properties: new AuthenticationProperties(new Dictionary<string, string?>
                    {
                        [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
                        [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "The user account is not active."
                    }));
            }

            // Create a new principal containing the updated claims
            var newPrincipal = await CreatePrincipalAsync(user, principal.GetScopes());
            newPrincipal.SetScopes(principal.GetScopes());

            _logger.LogInformation("Refresh token grant successful for user: {UserId}", user.Id);
            return SignIn(newPrincipal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        _logger.LogError("Unsupported grant type: {GrantType}", request.GrantType);
        throw new InvalidOperationException("The specified grant type is not supported.");
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