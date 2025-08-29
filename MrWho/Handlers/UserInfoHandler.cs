using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using MrWho.Data;
using MrWho.Models;
using OpenIddict.Abstractions;
using OpenIddict.Server;
using OpenIddict.Server.AspNetCore;
using System.Security.Claims;
using static OpenIddict.Server.OpenIddictServerEvents;
using Microsoft.AspNetCore.Http;

namespace MrWho.Handlers;

/// <summary>
/// Custom OpenIddict event handler for the UserInfo endpoint that delegates to IUserInfoHandler.
/// This keeps logic centralized while staying inside the OpenIddict pipeline (preferred standard approach).
/// </summary>
public sealed class CustomUserInfoHandler : IOpenIddictServerHandler<HandleUserInfoRequestContext>
{
    public static OpenIddictServerHandlerDescriptor Descriptor =>
        OpenIddictServerHandlerDescriptor.CreateBuilder<HandleUserInfoRequestContext>()
            .UseScopedHandler<CustomUserInfoHandler>()
            .SetOrder(OpenIddictServerHandlers.UserInfo.ValidateUserInfoRequest.Descriptor.Order + 500)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    private readonly IUserInfoHandler _userInfoHandler;
    private readonly ILogger<CustomUserInfoHandler> _logger;
    private readonly IHttpContextAccessor _httpContextAccessor;

    public CustomUserInfoHandler(IUserInfoHandler userInfoHandler, ILogger<CustomUserInfoHandler> logger, IHttpContextAccessor httpContextAccessor)
    {
        _userInfoHandler = userInfoHandler;
        _logger = logger;
        _httpContextAccessor = httpContextAccessor;
    }

    public async ValueTask HandleAsync(HandleUserInfoRequestContext context)
    {
        // If already handled/rejected, do nothing
        if (context.IsRequestHandled || context.IsRejected)
            return;

        // Use current HttpContext (passthrough NOT required because we handle inside pipeline)
        var httpContext = _httpContextAccessor.HttpContext;
        if (httpContext == null)
        {
            _logger.LogWarning("CustomUserInfoHandler: IHttpContextAccessor returned null HttpContext");
            return; // let default handlers continue (should not happen)
        }

        try
        {
            var result = await _userInfoHandler.HandleUserInfoRequestAsync(httpContext);

            // If result is challenge/forbid -> translate into OpenIddict rejection for consistent error payload
            switch (result)
            {
                case IStatusCodeHttpResult status when status.StatusCode == StatusCodes.Status401Unauthorized:
                    context.Reject(error: OpenIddictConstants.Errors.InvalidToken, description: "Unauthorized userinfo request");
                    return;
                case IStatusCodeHttpResult status when status.StatusCode == StatusCodes.Status403Forbidden:
                    context.Reject(error: OpenIddictConstants.Errors.InsufficientScope, description: "Forbidden userinfo request");
                    return;
                default:
                    // Execute result (writes JSON). Then mark handled so OpenIddict stops.
                    await result.ExecuteAsync(httpContext);
                    context.HandleRequest();
                    return;
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unhandled exception in custom UserInfo handler");
            context.Reject(error: OpenIddictConstants.Errors.ServerError, description: "UserInfo processing failure");
        }
    }
}

public interface IUserInfoHandler
{
    Task<IResult> HandleUserInfoRequestAsync(HttpContext context);
}

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

    public async Task<IResult> HandleUserInfoRequestAsync(HttpContext context)
    {
        if (context.User?.Identity?.IsAuthenticated != true)
        {
            _logger.LogWarning("UserInfo request unauthenticated principal");
            return Results.Unauthorized();
        }

        var subjectClaim = context.User.FindFirst(OpenIddictConstants.Claims.Subject);
        if (subjectClaim == null)
        {
            _logger.LogWarning("UserInfo request missing subject claim");
            return Results.BadRequest(new { error = OpenIddictConstants.Errors.InvalidToken, error_description = "Missing subject (sub) claim" });
        }

        var scopes = context.User.GetScopes();
        if (!scopes.Contains(OpenIddictConstants.Scopes.OpenId, StringComparer.OrdinalIgnoreCase))
        {
            _logger.LogWarning("UserInfo request without openid scope for subject {Sub}", subjectClaim.Value);
            return Results.BadRequest(new { error = OpenIddictConstants.Errors.InsufficientScope, error_description = "openid scope required" });
        }

        var user = await _userManager.FindByIdAsync(subjectClaim.Value);
        if (user == null)
        {
            _logger.LogWarning("UserInfo request for non-existent user: {SubjectId}", subjectClaim.Value);
            return Results.BadRequest(new { error = OpenIddictConstants.Errors.InvalidToken, error_description = "Unknown subject" });
        }

        _logger.LogDebug("UserInfo request for user {UserId} with scopes: {Scopes}", user.Id, string.Join(", ", scopes));

        var identityResources = await GetIdentityResourcesForScopesAsync(scopes);
        _logger.LogDebug("Loaded {Count} identity resources", identityResources.Count);

        var userInfo = await BuildUserInfoAsync(user, identityResources, scopes);
        await AddMissingStandardScopeClaimsAsync(userInfo, user, scopes, alreadyUsingResources: identityResources.Count > 0);

        _logger.LogDebug("UserInfo response for user {UserId} contains {ClaimCount} claims", user.Id, userInfo.Count);

        return Results.Json(userInfo);
    }

    private async Task<List<IdentityResource>> GetIdentityResourcesForScopesAsync(IEnumerable<string> scopes)
    {
        var scopeSet = scopes.Select(s => s.Trim()).ToHashSet(StringComparer.OrdinalIgnoreCase);
        if (scopeSet.Count == 0) return new();
        return await _context.IdentityResources
            .Include(ir => ir.UserClaims)
            .Where(ir => ir.IsEnabled && scopeSet.Contains(ir.Name))
            .ToListAsync();
    }

    private async Task<Dictionary<string, object>> BuildUserInfoAsync(
        IdentityUser user,
        List<IdentityResource> identityResources,
        IEnumerable<string> scopes)
    {
        var userInfo = new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase)
        {
            ["sub"] = user.Id
        };

        if (identityResources.Count == 0)
        {
            _logger.LogInformation("No identity resources matched; will rely on scope fallback");
            return userInfo;
        }

        var userClaims = await _userManager.GetClaimsAsync(user);
        var claimLookup = userClaims
            .GroupBy(c => c.Type, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => g.First().Value, StringComparer.OrdinalIgnoreCase);

        foreach (var resource in identityResources)
        {
            foreach (var rc in resource.UserClaims)
            {
                if (userInfo.ContainsKey(rc.ClaimType)) continue;
                if (!claimLookup.TryGetValue(rc.ClaimType, out var value) || string.IsNullOrWhiteSpace(value))
                {
                    _logger.LogTrace("Claim {Claim} absent for user {UserId}", rc.ClaimType, user.Id);
                    continue;
                }
                userInfo[rc.ClaimType] = value;
            }
        }
        return userInfo;
    }

    private async Task AddMissingStandardScopeClaimsAsync(Dictionary<string, object> userInfo, IdentityUser user, IEnumerable<string> scopes, bool alreadyUsingResources)
    {
        foreach (var scope in scopes)
        {
            await AddClaimsForScope(userInfo, user, scope, onlyIfMissing: alreadyUsingResources);
        }
    }

    private async Task AddClaimsForScope(Dictionary<string, object> userInfo, IdentityUser user, string scope, bool onlyIfMissing = false)
    {
        async Task Add(string claimType)
        {
            if (onlyIfMissing && userInfo.ContainsKey(claimType)) return;
            await AddClaimIfNotNull(userInfo, user, claimType);
        }

        switch (scope.ToLowerInvariant())
        {
            case "profile":
                await Add("name");
                await Add("given_name");
                await Add("family_name");
                await Add("preferred_username");
                await Add("picture");
                await Add("website");
                await Add("gender");
                await Add("birthdate");
                await Add("zoneinfo");
                await Add("locale");
                await Add("updated_at");
                break;
            case "email":
                await Add("email");
                await Add("email_verified");
                break;
            case "phone":
                await Add("phone_number");
                await Add("phone_number_verified");
                break;
            case "roles":
                // roles as array
                if (!userInfo.ContainsKey("role"))
                {
                    var roles = await GetUserRolesAsync(user);
                    if (roles.Length > 0) userInfo["role"] = roles;
                }
                break;
            case "address":
                await Add("address");
                break;
        }
    }

    private async Task AddClaimIfNotNull(Dictionary<string, object> userInfo, IdentityUser user, string claimType)
    {
        if (userInfo.ContainsKey(claimType)) return;
        var val = await GetClaimValueAsync(user, claimType);
        if (val is null) return;
        // Convert bool to lowercase true/false for OIDC consistency (e.g., email_verified)
        if (val is bool b) userInfo[claimType] = b; else userInfo[claimType] = val;
    }

    private async Task<object?> GetClaimValueAsync(IdentityUser user, string claimType)
    {
        return claimType switch
        {
            "sub" => user.Id,
            "email" => user.Email,
            "email_verified" => user.EmailConfirmed,
            "preferred_username" => user.UserName,
            "phone_number" => user.PhoneNumber,
            "phone_number_verified" => user.PhoneNumberConfirmed,
            "name" => await GetUserClaimValueAsync(user, "name") ?? GetUserDisplayName(user),
            "role" => await GetUserRolesAsync(user),
            _ => await GetUserClaimValueAsync(user, claimType)
        };
    }

    private string GetUserDisplayName(IdentityUser user)
    {
        if (string.IsNullOrEmpty(user.UserName)) return "Unknown User";
        if (user.UserName.Contains('@'))
        {
            var local = user.UserName.Split('@')[0];
            return ConvertToFriendlyName(local);
        }
        return ConvertToFriendlyName(user.UserName);
    }

    private string ConvertToFriendlyName(string input)
    {
        if (string.IsNullOrEmpty(input)) return "Unknown User";
        var friendly = input.Replace('.', ' ').Replace('_', ' ').Replace('-', ' ');
        return string.Join(" ", friendly
            .Split(' ', StringSplitOptions.RemoveEmptyEntries)
            .Select(w => char.ToUpper(w[0]) + w.Substring(1).ToLower()));
    }

    private async Task<string?> GetUserClaimValueAsync(IdentityUser user, string claimType)
    {
        try
        {
            var claims = await _userManager.GetClaimsAsync(user);
            return claims.FirstOrDefault(c => c.Type.Equals(claimType, StringComparison.OrdinalIgnoreCase))?.Value;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error reading claim {Claim} for user {UserId}", claimType, user.Id);
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