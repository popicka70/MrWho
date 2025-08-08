using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Authentication;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using System.Security.Claims;
using Microsoft.AspNetCore;
using MrWho.Services;

namespace MrWho.Handlers;

public interface ITokenHandler
{
    Task<IResult> HandleTokenRequestAsync(HttpContext context);
}

public class TokenHandler : ITokenHandler
{
    private readonly UserManager<IdentityUser> _userManager;
    private readonly SignInManager<IdentityUser> _signInManager;
    private readonly IClientCookieConfigurationService _cookieService;
    private readonly ILogger<TokenHandler> _logger;

    public TokenHandler(
        UserManager<IdentityUser> userManager,
        SignInManager<IdentityUser> signInManager,
        IClientCookieConfigurationService cookieService,
        ILogger<TokenHandler> logger)
    {
        _userManager = userManager;
        _signInManager = signInManager;
        _cookieService = cookieService;
        _logger = logger;
    }

    public async Task<IResult> HandleTokenRequestAsync(HttpContext context)
    {
        var request = context.GetOpenIddictServerRequest() ??
                      throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

        // Log the grant type for debugging
        _logger.LogDebug("Token request received: GrantType={GrantType}, ClientId={ClientId}", 
            request.GrantType, request.ClientId);

        if (request.IsPasswordGrantType())
        {
            return await HandlePasswordGrantAsync(context, request);
        }

        if (request.IsClientCredentialsGrantType())
        {
            return HandleClientCredentialsGrant(request);
        }

        if (request.IsAuthorizationCodeGrantType())
        {
            return await HandleAuthorizationCodeGrantAsync(context, request);
        }

        if (request.IsRefreshTokenGrantType())
        {
            return await HandleRefreshTokenGrantAsync(context, request);
        }

        throw new InvalidOperationException($"The specified grant type '{request.GrantType}' is not supported.");
    }

    private async Task<IResult> HandlePasswordGrantAsync(HttpContext context, OpenIddictRequest request)
    {
        var user = await _userManager.FindByNameAsync(request.Username!);

        if (user != null && await _userManager.CheckPasswordAsync(user, request.Password!))
        {
            // Get client-specific authentication scheme if available
            var clientId = request.ClientId!;
            var cookieScheme = _cookieService.GetCookieSchemeForClient(clientId);

            var identity = new ClaimsIdentity(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
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

            var principal = new ClaimsPrincipal(identity);
            principal.SetScopes(request.GetScopes());

            // Sign in with client-specific cookie scheme for session management
            try
            {
                await context.SignInAsync(cookieScheme, principal);
                _logger.LogDebug("Signed in user {Username} with client-specific scheme {Scheme}", 
                    user.UserName, cookieScheme);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to sign in with client-specific scheme {Scheme}, using default", 
                    cookieScheme);
                // Fallback to default identity scheme
                await _signInManager.SignInAsync(user, isPersistent: false);
            }

            return Results.SignIn(principal, authenticationScheme: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        var properties = new AuthenticationProperties(new Dictionary<string, string?>
        {
            [OpenIddictServerAspNetCoreConstants.Properties.Error] = OpenIddictConstants.Errors.InvalidGrant,
            [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "The username/password couple is invalid."
        });

        return Results.Forbid(properties, new[] { OpenIddictServerAspNetCoreDefaults.AuthenticationScheme });
    }

    private static IResult HandleClientCredentialsGrant(OpenIddictRequest request)
    {
        var identity = new ClaimsIdentity(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        identity.AddClaim(OpenIddictConstants.Claims.Subject, request.ClientId!);

        var principal = new ClaimsPrincipal(identity);
        principal.SetScopes(request.GetScopes());

        return Results.SignIn(principal, authenticationScheme: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }

    private async Task<IResult> HandleAuthorizationCodeGrantAsync(HttpContext context, OpenIddictRequest request)
    {
        // Try to authenticate with client-specific scheme first
        ClaimsPrincipal? principal = null;
        var clientId = request.ClientId!;
        var cookieScheme = _cookieService.GetCookieSchemeForClient(clientId);

        try
        {
            var clientAuthResult = await context.AuthenticateAsync(cookieScheme);
            if (clientAuthResult.Succeeded && clientAuthResult.Principal?.Identity?.IsAuthenticated == true)
            {
                principal = clientAuthResult.Principal;
                _logger.LogDebug("Authenticated authorization code with client-specific scheme {Scheme}", cookieScheme);
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Failed to authenticate with client-specific scheme {Scheme}", cookieScheme);
        }

        // Fallback to OpenIddict authentication
        if (principal == null)
        {
            var authenticateResult = await context.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
            principal = authenticateResult.Principal;
            _logger.LogDebug("Using OpenIddict authentication for authorization code");
        }
        
        if (principal == null)
        {
            _logger.LogWarning("Authorization code authentication failed: no principal found");
            return Results.Forbid(authenticationSchemes: new[] { OpenIddictServerAspNetCoreDefaults.AuthenticationScheme });
        }

        // Create a new identity for the access token with the claims from the authorization code
        var identity = new ClaimsIdentity(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        
        // Copy the claims from the principal stored in the authorization code
        var subjectClaim = principal.FindFirst(OpenIddictConstants.Claims.Subject);
        var nameClaim = principal.FindFirst(OpenIddictConstants.Claims.Name);
        var emailClaim = principal.FindFirst(OpenIddictConstants.Claims.Email);
        var preferredUsernameClaim = principal.FindFirst(OpenIddictConstants.Claims.PreferredUsername);
        
        if (subjectClaim != null)
            identity.AddClaim(OpenIddictConstants.Claims.Subject, subjectClaim.Value);
        if (nameClaim != null)
            identity.AddClaim(OpenIddictConstants.Claims.Name, nameClaim.Value);
        if (emailClaim != null)
            identity.AddClaim(OpenIddictConstants.Claims.Email, emailClaim.Value);
        if (preferredUsernameClaim != null)
            identity.AddClaim(OpenIddictConstants.Claims.PreferredUsername, preferredUsernameClaim.Value);

        // Copy role claims
        var roleClaims = principal.FindAll(OpenIddictConstants.Claims.Role);
        foreach (var roleClaim in roleClaims)
        {
            identity.AddClaim(OpenIddictConstants.Claims.Role, roleClaim.Value);
        }
        
        var newPrincipal = new ClaimsPrincipal(identity);
        newPrincipal.SetScopes(request.GetScopes());

        return Results.SignIn(newPrincipal, authenticationScheme: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }

    private async Task<IResult> HandleRefreshTokenGrantAsync(HttpContext context, OpenIddictRequest request)
    {
        // Authenticate the refresh token and extract the principal
        var authenticateResult = await context.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        var principal = authenticateResult.Principal;
        
        if (principal == null)
        {
            _logger.LogWarning("Refresh token authentication failed: no principal found");
            return Results.Forbid(authenticationSchemes: new[] { OpenIddictServerAspNetCoreDefaults.AuthenticationScheme });
        }

        // Extract the user ID from the refresh token principal
        var subjectClaim = principal.FindFirst(OpenIddictConstants.Claims.Subject);
        if (subjectClaim == null)
        {
            _logger.LogWarning("Refresh token authentication failed: no subject claim found");
            return Results.Forbid(authenticationSchemes: new[] { OpenIddictServerAspNetCoreDefaults.AuthenticationScheme });
        }

        // Get the user from the database to ensure they still exist and are valid
        var user = await _userManager.FindByIdAsync(subjectClaim.Value);
        if (user == null)
        {
            _logger.LogWarning("Refresh token authentication failed: user not found for subject {Subject}", subjectClaim.Value);
            return Results.Forbid(authenticationSchemes: new[] { OpenIddictServerAspNetCoreDefaults.AuthenticationScheme });
        }

        // Check if the user is still enabled (you can add additional checks here if needed)
        if (!user.EmailConfirmed && _userManager.Options.SignIn.RequireConfirmedEmail)
        {
            _logger.LogWarning("Refresh token authentication failed: user {UserName} email not confirmed", user.UserName);
            return Results.Forbid(authenticationSchemes: new[] { OpenIddictServerAspNetCoreDefaults.AuthenticationScheme });
        }

        // Create a new identity with fresh user information
        var identity = new ClaimsIdentity(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        identity.AddClaim(OpenIddictConstants.Claims.Subject, user.Id);
        identity.AddClaim(OpenIddictConstants.Claims.Email, user.Email!);
        identity.AddClaim(OpenIddictConstants.Claims.Name, user.UserName!);
        identity.AddClaim(OpenIddictConstants.Claims.PreferredUsername, user.UserName!);

        // Add any additional claims you might need (roles, etc.)
        var roles = await _userManager.GetRolesAsync(user);
        foreach (var role in roles)
        {
            identity.AddClaim(OpenIddictConstants.Claims.Role, role);
        }

        var newPrincipal = new ClaimsPrincipal(identity);
        newPrincipal.SetScopes(request.GetScopes());

        // Update client-specific session if available
        var clientId = request.ClientId!;
        var cookieScheme = _cookieService.GetCookieSchemeForClient(clientId);
        try
        {
            await context.SignInAsync(cookieScheme, newPrincipal);
            _logger.LogDebug("Updated client-specific session for user {UserName} with scheme {Scheme}", 
                user.UserName, cookieScheme);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Failed to update client-specific session with scheme {Scheme}", cookieScheme);
        }

        _logger.LogDebug("Refresh token grant successful for user: {UserName}", user.UserName);
        return Results.SignIn(newPrincipal, authenticationScheme: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }
}