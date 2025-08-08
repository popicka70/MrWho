using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using System.Security.Claims;

namespace MrWho.Services;

/// <summary>
/// Service for managing dynamic client-specific cookies using a single authentication scheme
/// </summary>
public interface IDynamicCookieService
{
    /// <summary>
    /// Signs in a user with a client-specific cookie while using the default authentication scheme
    /// </summary>
    Task SignInWithClientCookieAsync(string clientId, IdentityUser user, bool rememberMe = false);
    
    /// <summary>
    /// Checks if a user is authenticated for a specific client
    /// </summary>
    Task<bool> IsAuthenticatedForClientAsync(string clientId);
    
    /// <summary>
    /// Signs out a user from a specific client's cookie
    /// </summary>
    Task SignOutFromClientAsync(string clientId);
    
    /// <summary>
    /// Gets the authenticated user's principal for a specific client
    /// </summary>
    Task<ClaimsPrincipal?> GetClientPrincipalAsync(string clientId);
}