using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using MrWho.Data;
using MrWho.Models;
using System.Security.Claims;

namespace MrWho.Handlers;

/// <summary>
/// Interface for handling OpenID Connect UserInfo requests
/// </summary>
public interface IUserInfoHandler
{
    /// <summary>
    /// Handles UserInfo requests to return user profile information
    /// </summary>
    /// <param name="context">The HTTP context containing the request</param>
    /// <returns>The user info result</returns>
    Task<IResult> HandleUserInfoRequestAsync(HttpContext context);
}

/// <summary>
/// Implementation of UserInfo handler for OpenID Connect UserInfo endpoint
/// </summary>
public class UserInfoHandler : IUserInfoHandler
{
    private readonly UserManager<IdentityUser> _userManager;
    private readonly ApplicationDbContext _context;
    private readonly ILogger<UserInfoHandler> _logger;

    public UserInfoHandler(
        UserManager<IdentityUser> userManager,
        ApplicationDbContext context,
        ILogger<UserInfoHandler> logger)
    {
        _userManager = userManager;
        _context = context;
        _logger = logger;
    }

    /// <inheritdoc />
    public async Task<IResult> HandleUserInfoRequestAsync(HttpContext context)
    {
        // When called with a Bearer token, the user claims are in OpenIddict format
        // We need to extract the Subject claim to find the user
        var subjectClaim = context.User.FindFirst(OpenIddictConstants.Claims.Subject);

        if (subjectClaim == null)
        {
            _logger.LogWarning("UserInfo request without subject claim");
            return Results.Challenge(authenticationSchemes: new[] { OpenIddictServerAspNetCoreDefaults.AuthenticationScheme });
        }

        // Find the user by their ID (which is stored in the Subject claim)
        var user = await _userManager.FindByIdAsync(subjectClaim.Value);

        if (user == null)
        {
            _logger.LogWarning("UserInfo request for non-existent user: {SubjectId}", subjectClaim.Value);
            return Results.Challenge(authenticationSchemes: new[] { OpenIddictServerAspNetCoreDefaults.AuthenticationScheme });
        }

        // Get the scopes from the access token
        var scopes = context.User.GetScopes();
        _logger.LogDebug("UserInfo request for user {UserId} with scopes: {Scopes}",
            user.Id, string.Join(", ", scopes));

        // Load identity resources for the requested scopes
        var identityResources = await GetIdentityResourcesForScopesAsync(scopes);
        _logger.LogDebug("Found {IdentityResourceCount} identity resources for scopes: {Scopes}",
            identityResources.Count, string.Join(", ", scopes));

        // Build the user info response based on identity resources AND scopes (fallback)
        var userInfo = await BuildUserInfoAsync(user, identityResources, scopes);

        _logger.LogDebug("UserInfo response for user {UserId} contains {ClaimCount} claims",
            user.Id, userInfo.Count);

        return Results.Ok(userInfo);
    }

    private async Task<List<IdentityResource>> GetIdentityResourcesForScopesAsync(IEnumerable<string> scopes)
    {
        return await _context.IdentityResources
            .Include(ir => ir.UserClaims)
            .Include(ir => ir.Properties)
            .Where(ir => ir.IsEnabled && scopes.Contains(ir.Name))
            .ToListAsync();
    }

    private async Task<Dictionary<string, object>> BuildUserInfoAsync(
        IdentityUser user,
        List<IdentityResource> identityResources,
        IEnumerable<string> scopes)
    {
        var userInfo = new Dictionary<string, object>();

        // Always include the subject claim
        userInfo["sub"] = user.Id;

        // Process each identity resource if any exist
        foreach (var identityResource in identityResources)
        {
            _logger.LogDebug("Processing identity resource '{ResourceName}' with {ClaimCount} claims",
                identityResource.Name, identityResource.UserClaims.Count);

            foreach (var userClaim in identityResource.UserClaims)
            {
                var claimValue = await GetClaimValueAsync(user, userClaim.ClaimType);
                if (claimValue != null)
                {
                    // Use the exact claim type as the key
                    userInfo[userClaim.ClaimType] = claimValue;
                    _logger.LogDebug("Added claim '{ClaimType}' with value for user {UserId}",
                        userClaim.ClaimType, user.Id);
                }
                else
                {
                    _logger.LogDebug("Claim '{ClaimType}' has no value for user {UserId}",
                        userClaim.ClaimType, user.Id);
                }
            }
        }

        // FALLBACK: If no identity resources are found, include standard claims based on scopes
        if (identityResources.Count == 0)
        {
            _logger.LogInformation("No identity resources found, using scope-based claim mapping for user {UserId}", user.Id);
            
            foreach (var scope in scopes)
            {
                await AddClaimsForScope(userInfo, user, scope);
            }
        }

        return userInfo;
    }

    /// <summary>
    /// Add claims for a specific scope when no identity resources are configured
    /// </summary>
    private async Task AddClaimsForScope(Dictionary<string, object> userInfo, IdentityUser user, string scope)
    {
        switch (scope.ToLower())
        {
            case "profile":
                await AddClaimIfNotNull(userInfo, user, "name");
                await AddClaimIfNotNull(userInfo, user, "given_name");
                await AddClaimIfNotNull(userInfo, user, "family_name");
                await AddClaimIfNotNull(userInfo, user, "preferred_username");
                await AddClaimIfNotNull(userInfo, user, "picture");
                await AddClaimIfNotNull(userInfo, user, "website");
                await AddClaimIfNotNull(userInfo, user, "gender");
                await AddClaimIfNotNull(userInfo, user, "birthdate");
                await AddClaimIfNotNull(userInfo, user, "zoneinfo");
                await AddClaimIfNotNull(userInfo, user, "locale");
                await AddClaimIfNotNull(userInfo, user, "updated_at");
                _logger.LogDebug("Added profile scope claims for user {UserId}", user.Id);
                break;

            case "email":
                await AddClaimIfNotNull(userInfo, user, "email");
                await AddClaimIfNotNull(userInfo, user, "email_verified");
                _logger.LogDebug("Added email scope claims for user {UserId}", user.Id);
                break;

            case "phone":
                await AddClaimIfNotNull(userInfo, user, "phone_number");
                await AddClaimIfNotNull(userInfo, user, "phone_number_verified");
                _logger.LogDebug("Added phone scope claims for user {UserId}", user.Id);
                break;

            case "roles":
                await AddClaimIfNotNull(userInfo, user, "role");
                _logger.LogDebug("Added roles scope claims for user {UserId}", user.Id);
                break;

            case "address":
                await AddClaimIfNotNull(userInfo, user, "address");
                _logger.LogDebug("Added address scope claims for user {UserId}", user.Id);
                break;

            default:
                _logger.LogDebug("Unknown scope '{Scope}' - no default claims added", scope);
                break;
        }
    }

    /// <summary>
    /// Helper method to add a claim only if it has a value
    /// </summary>
    private async Task AddClaimIfNotNull(Dictionary<string, object> userInfo, IdentityUser user, string claimType)
    {
        if (!userInfo.ContainsKey(claimType)) // Don't overwrite existing claims
        {
            var claimValue = await GetClaimValueAsync(user, claimType);
            if (claimValue != null)
            {
                userInfo[claimType] = claimValue;
                _logger.LogDebug("Added claim '{ClaimType}' with value for user {UserId}", claimType, user.Id);
            }
        }
    }

    private async Task<object?> GetClaimValueAsync(IdentityUser user, string claimType)
    {
        return claimType switch
        {
            // Standard OpenID Connect claims
            "sub" => user.Id,
            "email" => user.Email,
            "email_verified" => user.EmailConfirmed,
            "preferred_username" => user.UserName,
            "phone_number" => user.PhoneNumber,
            "phone_number_verified" => user.PhoneNumberConfirmed,

            // For name claim, check user claims first, then fallback to username
            "name" => await GetUserClaimValueAsync(user, "name") ?? user.UserName,

            // Handle roles specially - return as array
            "role" => await GetUserRolesAsync(user),

            // For other claims, check user claims table
            _ => await GetUserClaimValueAsync(user, claimType)
        };
    }

    private async Task<string?> GetUserClaimValueAsync(IdentityUser user, string claimType)
    {
        try
        {
            var claims = await _userManager.GetClaimsAsync(user);
            return claims.FirstOrDefault(c => c.Type == claimType)?.Value;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error retrieving claim '{ClaimType}' for user {UserId}", claimType, user.Id);
            return null;
        }
    }

    private async Task<string[]> GetUserRolesAsync(IdentityUser user)
    {
        try
        {
            var roles = await _userManager.GetRolesAsync(user);
            return roles.ToArray();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error retrieving roles for user {UserId}", user.Id);
            return Array.Empty<string>();
        }
    }
}