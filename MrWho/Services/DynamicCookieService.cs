using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Identity;
using System.Security.Claims;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Abstractions.OpenIddictConstants.Claims;

namespace MrWho.Services;

/// <summary>
/// Implementation of dynamic client-specific cookie management
/// Uses consistent authentication scheme approach for both static and dynamic clients
/// </summary>
public class DynamicCookieService : IDynamicCookieService
{
    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly IClientCookieConfigurationService _cookieConfigService;
    private readonly UserManager<IdentityUser> _userManager;
    private readonly ILogger<DynamicCookieService> _logger;

    public DynamicCookieService(
        IHttpContextAccessor httpContextAccessor,
        IClientCookieConfigurationService cookieConfigService,
        UserManager<IdentityUser> userManager,
        ILogger<DynamicCookieService> logger)
    {
        _httpContextAccessor = httpContextAccessor;
        _cookieConfigService = cookieConfigService;
        _userManager = userManager;
        _logger = logger;
    }

    public async Task SignInWithClientCookieAsync(string clientId, IdentityUser user, bool rememberMe = false)
    {
        var context = _httpContextAccessor.HttpContext 
            ?? throw new InvalidOperationException("HttpContext is not available");

        try
        {
            // CONSISTENT APPROACH: All clients use proper authentication schemes
            var scheme = _cookieConfigService.GetCookieSchemeForClient(clientId);
            
            // Create claims identity for the authentication scheme
            var identity = new ClaimsIdentity(scheme);
            await AddUserClaimsToIdentity(identity, user);
            
            identity.AddClaim(new Claim("client_id", clientId));
            _logger.LogDebug("🔧 Added client_id claim for dynamic client {ClientId}", clientId);

            var principal = new ClaimsPrincipal(identity);
            var properties = new AuthenticationProperties
            {
                IsPersistent = rememberMe,
                ExpiresUtc = rememberMe ? DateTimeOffset.UtcNow.AddDays(30) : DateTimeOffset.UtcNow.AddHours(24)
            };

            await context.SignInAsync(scheme, principal, properties);
            
            _logger.LogDebug("🔧 Signed in user {UserName} with dynamic scheme {Scheme} for client {ClientId}", 
                user.UserName, scheme, clientId);
        }
        catch (Exception ex) when (ex.Source == "Microsoft.AspNetCore.Authentication.Cookies")
        {
            _logger.LogWarning("Failed to sign in user {UserName} for client {ClientId}", user.UserName, clientId);
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to sign in user {UserName} for client {ClientId}", user.UserName, clientId);
            throw;
        }
    }

    public async Task<bool> IsAuthenticatedForClientAsync(string clientId)
    {
        var context = _httpContextAccessor.HttpContext 
            ?? throw new InvalidOperationException("HttpContext is not available");

        try
        {
            // CONSISTENT APPROACH: All clients (static and dynamic) use authentication schemes
            var scheme = _cookieConfigService.GetCookieSchemeForClient(clientId);
            var authResult = await context.AuthenticateAsync(scheme);
            
            if (!authResult.Succeeded || authResult.Principal?.Identity?.IsAuthenticated != true)
            {
                return false;
            }

            // For dynamic clients, validate that this authentication result is for the correct client
            var clientIdClaim = authResult.Principal.FindFirst("client_id");
            if (clientIdClaim?.Value != clientId)
            {
                _logger.LogDebug("🔧 Authentication succeeded but for different client. Expected: {ExpectedClient}, Found: {ActualClient}", 
                    clientId, clientIdClaim?.Value ?? "NULL");
                return false;
            }
            
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to check authentication for client {ClientId}", clientId);
            return false;
        }
    }

    public async Task SignOutFromClientAsync(string clientId)
    {
        var context = _httpContextAccessor.HttpContext 
            ?? throw new InvalidOperationException("HttpContext is not available");

        try
        {
            // CONSISTENT APPROACH: All clients use proper authentication schemes
            var scheme = _cookieConfigService.GetCookieSchemeForClient(clientId);
            await context.SignOutAsync(scheme);
            
            _logger.LogDebug("🔧 Signed out from dynamic scheme {Scheme} for client {ClientId}", scheme, clientId);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to sign out for client {ClientId}", clientId);
            throw;
        }
    }

    public async Task<ClaimsPrincipal?> GetClientPrincipalAsync(string clientId)
    {
        var context = _httpContextAccessor.HttpContext 
            ?? throw new InvalidOperationException("HttpContext is not available");

        try
        {
            // CONSISTENT APPROACH: All clients (static and dynamic) use authentication schemes
            var scheme = _cookieConfigService.GetCookieSchemeForClient(clientId);
            var authResult = await context.AuthenticateAsync(scheme);
            
            if (!authResult.Succeeded || authResult.Principal?.Identity?.IsAuthenticated != true)
            {
                _logger.LogDebug("🔧 No valid authentication for client {ClientId} using scheme {SchemeName}", 
                    clientId, scheme);
                return null;
            }

            // For dynamic clients, validate that this authentication result is for the correct client
            var clientIdClaim = authResult.Principal.FindFirst("client_id");
            if (clientIdClaim?.Value != clientId)
            {
                _logger.LogDebug("🔧 Authentication succeeded but for different client. Expected: {ExpectedClient}, Found: {ActualClient}", 
                    clientId, clientIdClaim?.Value ?? "NULL");
                return null;
            }
                
            _logger.LogDebug("🔧 DYNAMIC SCHEME SUCCESS: Client {ClientId} authenticated using dynamic scheme {SchemeName}", 
                clientId, scheme);

            return authResult.Principal;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to get principal for client {ClientId}", clientId);
            return null;
        }
    }

    private async Task AddUserClaimsToIdentity(ClaimsIdentity identity, IdentityUser user)
    {
        identity.AddClaim(new Claim(Claims.Subject, user.Id));
        identity.AddClaim(new Claim(Claims.Email, user.Email ?? ""));
        identity.AddClaim(new Claim(Claims.Name, await GetUserDisplayNameAsync(user)));
        identity.AddClaim(new Claim(Claims.PreferredUsername, user.UserName ?? ""));

        // Add additional user claims from the database
        try
        {
            var userClaims = await _userManager.GetClaimsAsync(user);
            foreach (var claim in userClaims)
            {
                identity.AddClaim(claim);
            }

            // Add roles
            var roles = await _userManager.GetRolesAsync(user);
            foreach (var role in roles)
            {
                identity.AddClaim(new Claim(Claims.Role, role));
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error adding user claims to identity for user {UserId}", user.Id);
        }
    }

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
}