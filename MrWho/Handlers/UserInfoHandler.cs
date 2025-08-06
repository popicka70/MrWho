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

        // Build the user info response based on identity resources
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

        // Process each identity resource
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

        return userInfo;
    }

    private async Task<object?> GetClaimValueAsync(IdentityUser user, string claimType)
    {
        return claimType switch
        {
            // Standard OpenID Connect claims
            "sub" => user.Id,
            "email" => user.Email,
            "email_verified" => user.EmailConfirmed,
            "name" => user.UserName,
            "preferred_username" => user.UserName,
            "phone_number" => user.PhoneNumber,
            "phone_number_verified" => user.PhoneNumberConfirmed,

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