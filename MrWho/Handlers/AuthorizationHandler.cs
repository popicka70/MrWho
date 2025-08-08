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

        // CRITICAL: Only check authentication with the client-specific scheme, NO FALLBACK
        ClaimsPrincipal? principal = null;
        try
        {
            var authResult = await context.AuthenticateAsync(cookieScheme);
            if (authResult.Succeeded && authResult.Principal?.Identity?.IsAuthenticated == true)
            {
                principal = authResult.Principal;
                _logger.LogDebug("User already authenticated with client-specific scheme {Scheme}", cookieScheme);
            }
            else
            {
                _logger.LogDebug("User not authenticated with client-specific scheme {Scheme}", cookieScheme);
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Failed to authenticate with client-specific scheme {Scheme}", cookieScheme);
        }

        // If user is not authenticated with THIS client's scheme, trigger login
        if (principal == null)
        {
            _logger.LogDebug("User not authenticated for client {ClientId}, triggering login challenge with scheme {Scheme}", 
                clientId, cookieScheme);
            
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

        // User is authenticated with the correct client scheme, create authorization code
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

        // Get requested scopes to determine claim destinations
        var scopes = request.GetScopes();

        // Create claims for the authorization code with proper destinations
        var subClaim = new Claim(OpenIddictConstants.Claims.Subject, user.Id);
        subClaim.SetDestinations(OpenIddictConstants.Destinations.AccessToken, OpenIddictConstants.Destinations.IdentityToken);
        identity.AddClaim(subClaim);

        var emailClaim = new Claim(OpenIddictConstants.Claims.Email, user.Email!);
        emailClaim.SetDestinations(OpenIddictConstants.Destinations.AccessToken, OpenIddictConstants.Destinations.IdentityToken);
        identity.AddClaim(emailClaim);
        
        // Get the user's name claim, fallback to friendly name from username
        var userName = await GetUserNameClaimAsync(user);
        var nameClaim = new Claim(OpenIddictConstants.Claims.Name, userName);
        nameClaim.SetDestinations(OpenIddictConstants.Destinations.AccessToken, OpenIddictConstants.Destinations.IdentityToken);
        identity.AddClaim(nameClaim);

        var preferredUsernameClaim = new Claim(OpenIddictConstants.Claims.PreferredUsername, user.UserName!);
        preferredUsernameClaim.SetDestinations(OpenIddictConstants.Destinations.AccessToken, OpenIddictConstants.Destinations.IdentityToken);
        identity.AddClaim(preferredUsernameClaim);

        // Add other profile claims with proper destinations if available
        await AddProfileClaimsAsync(identity, user, scopes);

        // Add roles with proper destinations
        var roles = await _userManager.GetRolesAsync(user);
        foreach (var role in roles)
        {
            var roleClaim = new Claim(OpenIddictConstants.Claims.Role, role);
            roleClaim.SetDestinations(OpenIddictConstants.Destinations.AccessToken, OpenIddictConstants.Destinations.IdentityToken);
            identity.AddClaim(roleClaim);
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

    /// <summary>
    /// Get the user's name claim, with intelligent fallback to username conversion
    /// </summary>
    private async Task<string> GetUserNameClaimAsync(IdentityUser user)
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
    /// Add additional profile claims with proper destinations if available
    /// </summary>
    private async Task AddProfileClaimsAsync(ClaimsIdentity identity, IdentityUser user, IEnumerable<string> scopes)
    {
        try
        {
            var claims = await _userManager.GetClaimsAsync(user);
            
            // Only include profile claims if profile scope is requested
            if (scopes.Contains(OpenIddictConstants.Scopes.Profile))
            {
                // Add given_name if available
                var givenName = claims.FirstOrDefault(c => c.Type == "given_name")?.Value;
                if (!string.IsNullOrEmpty(givenName))
                {
                    var givenNameClaim = new Claim(OpenIddictConstants.Claims.GivenName, givenName);
                    givenNameClaim.SetDestinations(OpenIddictConstants.Destinations.AccessToken, OpenIddictConstants.Destinations.IdentityToken);
                    identity.AddClaim(givenNameClaim);
                }

                // Add family_name if available
                var familyName = claims.FirstOrDefault(c => c.Type == "family_name")?.Value;
                if (!string.IsNullOrEmpty(familyName))
                {
                    var familyNameClaim = new Claim(OpenIddictConstants.Claims.FamilyName, familyName);
                    familyNameClaim.SetDestinations(OpenIddictConstants.Destinations.AccessToken, OpenIddictConstants.Destinations.IdentityToken);
                    identity.AddClaim(familyNameClaim);
                }

                // Add other profile claims as needed
                var picture = claims.FirstOrDefault(c => c.Type == "picture")?.Value;
                if (!string.IsNullOrEmpty(picture))
                {
                    var pictureClaim = new Claim(OpenIddictConstants.Claims.Picture, picture);
                    pictureClaim.SetDestinations(OpenIddictConstants.Destinations.AccessToken, OpenIddictConstants.Destinations.IdentityToken);
                    identity.AddClaim(pictureClaim);
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error retrieving profile claims for user {UserId}", user.Id);
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