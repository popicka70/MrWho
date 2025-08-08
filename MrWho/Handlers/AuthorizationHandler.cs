using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Authentication;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using System.Security.Claims;
using MrWho.Services;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.AspNetCore;

namespace MrWho.Handlers;

public interface IOidcAuthorizationHandler
{
    Task<IResult> HandleAuthorizationRequestAsync(HttpContext context);
}

public class OidcAuthorizationHandler : IOidcAuthorizationHandler
{
    private readonly UserManager<IdentityUser> _userManager;
    private readonly SignInManager<IdentityUser> _signInManager;
    private readonly IClientCookieConfigurationService _cookieService;
    private readonly ILogger<OidcAuthorizationHandler> _logger;

    public OidcAuthorizationHandler(
        UserManager<IdentityUser> userManager,
        SignInManager<IdentityUser> signInManager,
        IClientCookieConfigurationService cookieService,
        ILogger<OidcAuthorizationHandler> logger)
    {
        _userManager = userManager;
        _signInManager = signInManager;
        _cookieService = cookieService;
        _logger = logger;
    }

    public async Task<IResult> HandleAuthorizationRequestAsync(HttpContext context)
    {
        var request = context.GetOpenIddictServerRequest() ??
                      throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

        var clientId = request.ClientId!;
        _logger.LogDebug("Authorization request received for client {ClientId}", clientId);

        // Get client-specific authentication scheme
        var cookieScheme = _cookieService.GetCookieSchemeForClient(clientId);

        // Check if user is already authenticated with this client's scheme
        ClaimsPrincipal? principal = null;
        try
        {
            var authResult = await context.AuthenticateAsync(cookieScheme);
            if (authResult.Succeeded && authResult.Principal?.Identity?.IsAuthenticated == true)
            {
                principal = authResult.Principal;
                _logger.LogDebug("User already authenticated with client-specific scheme {Scheme}", cookieScheme);
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Failed to authenticate with client-specific scheme {Scheme}", cookieScheme);
        }

        // Fallback to default Identity authentication if not authenticated with client scheme
        if (principal == null)
        {
            try
            {
                var defaultAuthResult = await context.AuthenticateAsync("Identity.Application");
                if (defaultAuthResult.Succeeded && defaultAuthResult.Principal?.Identity?.IsAuthenticated == true)
                {
                    principal = defaultAuthResult.Principal;
                    _logger.LogDebug("User authenticated with default Identity scheme");
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Failed to authenticate with default Identity scheme");
            }
        }

        // If user is not authenticated, trigger login with client-specific scheme
        if (principal == null)
        {
            _logger.LogDebug("User not authenticated, triggering login challenge with scheme {Scheme}", cookieScheme);
            
            // Store the authorization request parameters for later use
            var properties = new AuthenticationProperties
            {
                RedirectUri = context.Request.GetEncodedUrl(),
                Items = 
                {
                    ["client_id"] = clientId
                }
            };

            // For web applications, redirect to the login page with client information
            if (request.ResponseType == "code") // Authorization Code Flow (web apps)
            {
                var loginUrl = $"/connect/login?returnUrl={Uri.EscapeDataString(context.Request.GetEncodedUrl())}&clientId={Uri.EscapeDataString(clientId)}";
                return Results.Redirect(loginUrl);
            }

            // For other flows, challenge with client-specific cookie scheme
            return Results.Challenge(properties, new[] { cookieScheme });
        }

        // User is authenticated, create authorization code
        var identity = new ClaimsIdentity(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);

        // Get user from database to ensure we have the latest information
        var subjectClaim = principal.FindFirst(ClaimTypes.NameIdentifier) ?? 
                          principal.FindFirst(OpenIddictConstants.Claims.Subject);
        
        if (subjectClaim == null)
        {
            _logger.LogWarning("No subject claim found in authenticated principal");
            return Results.Forbid();
        }

        var user = await _userManager.FindByIdAsync(subjectClaim.Value);
        if (user == null)
        {
            _logger.LogWarning("User not found for subject {Subject}", subjectClaim.Value);
            return Results.Forbid();
        }

        // Create claims for the authorization code
        identity.AddClaim(OpenIddictConstants.Claims.Subject, user.Id);
        identity.AddClaim(OpenIddictConstants.Claims.Email, user.Email!);
        identity.AddClaim(OpenIddictConstants.Claims.Name, user.UserName!);
        identity.AddClaim(OpenIddictConstants.Claims.PreferredUsername, user.UserName!);

        // Add roles
        var roles = await _userManager.GetRolesAsync(user);
        foreach (var role in roles)
        {
            identity.AddClaim(OpenIddictConstants.Claims.Role, role);
        }

        var authPrincipal = new ClaimsPrincipal(identity);
        authPrincipal.SetScopes(request.GetScopes());

        // Sign in the user with the client-specific scheme if not already done
        if (!await IsUserSignedInWithScheme(context, cookieScheme, user.Id))
        {
            try
            {
                await context.SignInAsync(cookieScheme, authPrincipal);
                _logger.LogDebug("Signed in user {UserName} with client-specific scheme {Scheme}", 
                    user.UserName, cookieScheme);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to sign in with client-specific scheme {Scheme}", cookieScheme);
            }
        }

        _logger.LogDebug("Authorization granted for user {UserName} and client {ClientId}", 
            user.UserName, clientId);

        return Results.SignIn(authPrincipal, authenticationScheme: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }

    private async Task<bool> IsUserSignedInWithScheme(HttpContext context, string scheme, string userId)
    {
        try
        {
            var authResult = await context.AuthenticateAsync(scheme);
            if (authResult.Succeeded && authResult.Principal?.Identity?.IsAuthenticated == true)
            {
                var subjectClaim = authResult.Principal.FindFirst(ClaimTypes.NameIdentifier) ??
                                  authResult.Principal.FindFirst(OpenIddictConstants.Claims.Subject);
                return subjectClaim?.Value == userId;
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Error checking authentication status for scheme {Scheme}", scheme);
        }
        return false;
    }
}