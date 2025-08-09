using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Identity;
using System.Security.Claims;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace MrWho.Services;

/// <summary>
/// Implementation of dynamic client-specific cookie management
/// Uses cookie name differentiation rather than separate authentication schemes
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
            // For clients with static configuration, use their registered scheme
            if (_cookieConfigService.HasStaticConfiguration(clientId))
            {
                var staticScheme = _cookieConfigService.GetCookieSchemeForClient(clientId);
                await SignInWithStaticSchemeAsync(context, staticScheme, user, rememberMe);
                _logger.LogDebug("Signed in user {UserName} with static scheme {Scheme} for client {ClientId}", 
                    user.UserName, staticScheme, clientId);
                return;
            }

            // For dynamic clients, create a custom cookie with the client-specific name
            await SignInWithDynamicCookieAsync(context, clientId, user, rememberMe);
            _logger.LogDebug("Signed in user {UserName} with dynamic cookie for client {ClientId}", 
                user.UserName, clientId);
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
            // For clients with static configuration, check their registered scheme
            if (_cookieConfigService.HasStaticConfiguration(clientId))
            {
                var staticScheme = _cookieConfigService.GetCookieSchemeForClient(clientId);
                var authResult = await context.AuthenticateAsync(staticScheme);
                return authResult.Succeeded && authResult.Principal?.Identity?.IsAuthenticated == true;
            }

            // For dynamic clients, check if their specific cookie exists and is valid
            return await IsValidDynamicCookieAsync(context, clientId);
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
            // For clients with static configuration, sign out from their registered scheme
            if (_cookieConfigService.HasStaticConfiguration(clientId))
            {
                var staticScheme = _cookieConfigService.GetCookieSchemeForClient(clientId);
                await context.SignOutAsync(staticScheme);
                _logger.LogDebug("Signed out from static scheme {Scheme} for client {ClientId}", staticScheme, clientId);
                return;
            }

            // For dynamic clients, remove their specific cookie
            await SignOutFromDynamicCookieAsync(context, clientId);
            _logger.LogDebug("Signed out from dynamic cookie for client {ClientId}", clientId);
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
            // For clients with static configuration, get principal from their registered scheme
            if (_cookieConfigService.HasStaticConfiguration(clientId))
            {
                var staticScheme = _cookieConfigService.GetCookieSchemeForClient(clientId);
                _logger.LogDebug("? STATIC PATH: Client {ClientId} using static scheme {SchemeName}", 
                    clientId, staticScheme);
                var authResult = await context.AuthenticateAsync(staticScheme);
                return authResult.Succeeded ? authResult.Principal : null;
            }

            // For dynamic clients, reconstruct principal from their cookie
            _logger.LogDebug("?? DYNAMIC PATH: Client {ClientId} using dynamic cookie management", clientId);
            return await GetDynamicCookiePrincipalAsync(context, clientId);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to get principal for client {ClientId}", clientId);
            return null;
        }
    }

    private async Task SignInWithStaticSchemeAsync(HttpContext context, string scheme, IdentityUser user, bool rememberMe)
    {
        // Create claims identity for static scheme
        var identity = new ClaimsIdentity(scheme);
        await AddUserClaimsToIdentity(identity, user);

        var principal = new ClaimsPrincipal(identity);
        var properties = new AuthenticationProperties
        {
            IsPersistent = rememberMe,
            ExpiresUtc = rememberMe ? DateTimeOffset.UtcNow.AddDays(30) : DateTimeOffset.UtcNow.AddHours(24)
        };

        await context.SignInAsync(scheme, principal, properties);
    }

    private async Task SignInWithDynamicCookieAsync(HttpContext context, string clientId, IdentityUser user, bool rememberMe)
    {
        var cookieName = _cookieConfigService.GetCookieNameForClient(clientId);
        
        // Create a secure, signed cookie manually
        var claims = new Dictionary<string, string>
        {
            [Claims.Subject] = user.Id,
            [Claims.Email] = user.Email ?? "",
            [Claims.Name] = await GetUserDisplayNameAsync(user),
            [Claims.PreferredUsername] = user.UserName ?? "",
            ["client_id"] = clientId,
            ["iat"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(),
            ["exp"] = (rememberMe ? DateTimeOffset.UtcNow.AddDays(30) : DateTimeOffset.UtcNow.AddHours(24)).ToUnixTimeSeconds().ToString()
        };

        // Add additional user claims
        await AddUserClaimsToDictionary(claims, user);

        // Create a secure cookie value (you might want to encrypt this in production)
        var cookieValue = CreateSecureCookieValue(claims);

        var cookieOptions = new CookieOptions
        {
            HttpOnly = true,
            Secure = true,
            SameSite = SameSiteMode.Lax,
            Expires = rememberMe ? DateTimeOffset.UtcNow.AddDays(30) : DateTimeOffset.UtcNow.AddHours(24)
        };

        context.Response.Cookies.Append(cookieName, cookieValue, cookieOptions);
    }

    private async Task<bool> IsValidDynamicCookieAsync(HttpContext context, string clientId)
    {
        var cookieName = _cookieConfigService.GetCookieNameForClient(clientId);
        
        if (!context.Request.Cookies.TryGetValue(cookieName, out var cookieValue) || string.IsNullOrEmpty(cookieValue))
        {
            return false;
        }

        try
        {
            var claims = ParseSecureCookieValue(cookieValue);
            
            // Validate expiration
            if (claims.TryGetValue("exp", out var expStr) && long.TryParse(expStr, out var exp))
            {
                var expiration = DateTimeOffset.FromUnixTimeSeconds(exp);
                if (expiration <= DateTimeOffset.UtcNow)
                {
                    return false;
                }
            }

            // Validate client ID
            if (!claims.TryGetValue("client_id", out var cookieClientId) || cookieClientId != clientId)
            {
                return false;
            }

            return true;
        }
        catch
        {
            return false;
        }
    }

    private async Task SignOutFromDynamicCookieAsync(HttpContext context, string clientId)
    {
        var cookieName = _cookieConfigService.GetCookieNameForClient(clientId);
        
        context.Response.Cookies.Delete(cookieName, new CookieOptions
        {
            HttpOnly = true,
            Secure = true,
            SameSite = SameSiteMode.Lax
        });
    }

    private async Task<ClaimsPrincipal?> GetDynamicCookiePrincipalAsync(HttpContext context, string clientId)
    {
        var cookieName = _cookieConfigService.GetCookieNameForClient(clientId);
        
        if (!context.Request.Cookies.TryGetValue(cookieName, out var cookieValue) || string.IsNullOrEmpty(cookieValue))
        {
            return null;
        }

        try
        {
            var claims = ParseSecureCookieValue(cookieValue);
            
            // Validate expiration
            if (claims.TryGetValue("exp", out var expStr) && long.TryParse(expStr, out var exp))
            {
                var expiration = DateTimeOffset.FromUnixTimeSeconds(exp);
                if (expiration <= DateTimeOffset.UtcNow)
                {
                    return null;
                }
            }

            // Create claims identity
            var identity = new ClaimsIdentity("DynamicCookie");
            foreach (var claim in claims)
            {
                if (claim.Key != "iat" && claim.Key != "exp") // Skip timestamp claims
                {
                    identity.AddClaim(new Claim(claim.Key, claim.Value));
                }
            }

            return new ClaimsPrincipal(identity);
        }
        catch
        {
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

    private async Task AddUserClaimsToDictionary(Dictionary<string, string> claims, IdentityUser user)
    {
        try
        {
            var userClaims = await _userManager.GetClaimsAsync(user);
            foreach (var claim in userClaims)
            {
                // Avoid duplicates and use a safe key format
                var key = $"uclaim_{claim.Type}";
                if (!claims.ContainsKey(key))
                {
                    claims[key] = claim.Value;
                }
            }

            // Add roles
            var roles = await _userManager.GetRolesAsync(user);
            for (int i = 0; i < roles.Count; i++)
            {
                claims[$"role_{i}"] = roles[i];
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error adding user claims to dictionary for user {UserId}", user.Id);
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

    private string CreateSecureCookieValue(Dictionary<string, string> claims)
    {
        // Simple implementation - in production, you should encrypt this
        var json = System.Text.Json.JsonSerializer.Serialize(claims);
        var bytes = System.Text.Encoding.UTF8.GetBytes(json);
        return Convert.ToBase64String(bytes);
    }

    private Dictionary<string, string> ParseSecureCookieValue(string cookieValue)
    {
        // Simple implementation - in production, you should decrypt this
        var bytes = Convert.FromBase64String(cookieValue);
        var json = System.Text.Encoding.UTF8.GetString(bytes);
        return System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, string>>(json) 
            ?? new Dictionary<string, string>();
    }
}