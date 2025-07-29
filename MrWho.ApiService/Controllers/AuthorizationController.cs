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

        // Retrieve the user principal stored in the authentication cookie
        var result = await HttpContext.AuthenticateAsync(IdentityConstants.ApplicationScheme);

        // If the user principal can't be extracted or the cookie is too old, redirect to login
        if (!result.Succeeded)
        {
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
        var user = await _userManager.GetUserAsync(result.Principal!) ??
            throw new InvalidOperationException("The user details cannot be retrieved.");

        if (!user.IsActive)
        {
            return Forbid(
                authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                properties: new AuthenticationProperties(new Dictionary<string, string?>
                {
                    [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
                    [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "The user account is not active."
                }));
        }

        // Retrieve the application details from the database
        var application = await _applicationManager.FindByClientIdAsync(request.ClientId!) ??
            throw new InvalidOperationException("Details concerning the calling client application cannot be found.");

        // Create the claims principal that will be used to create the authorization code/access token
        var principal = await CreatePrincipalAsync(user, request.GetScopes());

        // Set the list of scopes granted to the client application
        principal.SetScopes(request.GetScopes());

        return SignIn(principal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }

    [HttpPost("token")]
    [IgnoreAntiforgeryToken]
    [Produces("application/json")]
    public async Task<IActionResult> Exchange()
    {
        var request = HttpContext.GetOpenIddictServerRequest() ??
            throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

        if (request.IsAuthorizationCodeGrantType())
        {
            // Retrieve the claims principal stored in the authorization code
            var principal = (await HttpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme)).Principal!;

            // Retrieve the user profile corresponding to the authorization code
            var user = await _userManager.FindByIdAsync(principal.GetClaim(Claims.Subject)!);
            if (user == null)
            {
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

            return SignIn(newPrincipal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        if (request.IsPasswordGrantType())
        {
            var user = await _userManager.FindByEmailAsync(request.Username!) ??
                       await _userManager.FindByNameAsync(request.Username!);

            if (user == null || !user.IsActive)
            {
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
                var properties = new AuthenticationProperties(new Dictionary<string, string?>
                {
                    [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
                    [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] =
                        "The username/password couple is invalid."
                });

                return Forbid(properties, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
            }

            var principal = await CreatePrincipalAsync(user, request.GetScopes());
            return SignIn(principal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        if (request.IsClientCredentialsGrantType())
        {
            var application = await _applicationManager.FindByClientIdAsync(request.ClientId!);
            if (application == null)
            {
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

            return SignIn(principal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        if (request.IsRefreshTokenGrantType())
        {
            // Retrieve the claims principal stored in the refresh token
            var principal = (await HttpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme)).Principal!;

            // Retrieve the user profile corresponding to the refresh token
            var user = await _userManager.FindByIdAsync(principal.GetClaim(Claims.Subject)!);
            if (user == null)
            {
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

            return SignIn(newPrincipal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

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