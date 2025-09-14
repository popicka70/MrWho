using System.Security.Claims;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using MrWho.Data;
using MrWho.Models;
using OpenIddict.Abstractions;
using OpenIddict.Server;
using static OpenIddict.Server.OpenIddictServerEvents;

namespace MrWho.Handlers;

public sealed class CustomUserInfoHandler : IOpenIddictServerHandler<HandleUserInfoRequestContext>
{
    public static OpenIddictServerHandlerDescriptor Descriptor =>
        OpenIddictServerHandlerDescriptor.CreateBuilder<HandleUserInfoRequestContext>()
            .UseScopedHandler<CustomUserInfoHandler>()
            .SetOrder(OpenIddictServerHandlers.UserInfo.HandleUserInfoRequest.Descriptor.Order - 200)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    private readonly UserManager<IdentityUser> _userManager;
    private readonly ApplicationDbContext _db;
    private readonly ILogger<CustomUserInfoHandler> _logger;

    public CustomUserInfoHandler(UserManager<IdentityUser> userManager, ApplicationDbContext db, ILogger<CustomUserInfoHandler> logger)
    {
        _userManager = userManager;
        _db = db;
        _logger = logger;
    }

    public async ValueTask HandleAsync(HandleUserInfoRequestContext context)
    {
        if (context.IsRequestHandled || context.IsRejected) {
            return;
        }

        // OpenIddict exposes a Principal property on the specific context type even if not visible through events alias.
        var principal = context.AccessTokenPrincipal;
        if (principal is null)
        {
            context.Reject(OpenIddictConstants.Errors.InvalidToken, "Missing principal");
            return;
        }

        // Extract subject (sub)
        var subject = principal.FindFirst(OpenIddictConstants.Claims.Subject)?.Value;
        if (string.IsNullOrWhiteSpace(subject))
        {
            _logger.LogWarning("UserInfo: subject claim missing");
            context.Reject(OpenIddictConstants.Errors.InvalidToken, "Subject claim missing");
            return;
        }

        // Ensure openid scope requested (spec requirement)
        var scopes = principal.GetScopes();
        if (!scopes.Contains(OpenIddictConstants.Scopes.OpenId, StringComparer.OrdinalIgnoreCase))
        {
            _logger.LogWarning("UserInfo: openid scope not present for subject {Sub}", subject);
            context.Reject(OpenIddictConstants.Errors.InsufficientScope, "openid scope required");
            return;
        }

        // Load user
        var user = await _userManager.FindByIdAsync(subject);
        if (user == null)
        {
            _logger.LogWarning("UserInfo: user not found for subject {Sub}", subject);
            context.Reject(OpenIddictConstants.Errors.InvalidToken, "Unknown subject");
            return;
        }

        // Optional: enforce client-level permission to access userinfo endpoint if we can resolve client id
        var clientId = context.Request?.ClientId;
        if (!string.IsNullOrWhiteSpace(clientId))
        {
            var client = await _db.Clients.AsNoTracking().FirstOrDefaultAsync(c => c.ClientId == clientId);
            if (client?.AllowAccessToUserInfoEndpoint == false)
            {
                _logger.LogWarning("UserInfo: client {ClientId} not allowed to access userinfo endpoint", clientId);
                context.Reject(OpenIddictConstants.Errors.UnauthorizedClient, "Client not allowed to access userinfo");
                return;
            }
        }

        _logger.LogDebug("UserInfo: building response for user {UserId} client {ClientId} scopes {Scopes}", user.Id, clientId, string.Join(" ", scopes));

        // Identity resources mapping
        var identityResources = await GetIdentityResourcesForScopesAsync(scopes);
        var payload = await BuildUserInfoAsync(user, identityResources, scopes);
        await AddMissingStandardScopeClaimsAsync(payload, user, scopes, identityResources.Count > 0);

        _logger.LogDebug("UserInfo: returning {ClaimCount} claims for user {UserId}", payload.Count, user.Id);

        foreach (var kvp in payload)
        {
            switch (kvp.Value)
            {
                case string s:
                    context.Claims[kvp.Key] = s; break;
                case bool b:
                    context.Claims[kvp.Key] = b; break;
                case string[] sa:
                    context.Claims[kvp.Key] = string.Join(" ", sa); break;
                case IEnumerable<string> enumerable:
                    var arr = enumerable.ToArray();
                    context.Claims[kvp.Key] = string.Join(" ", arr); break;
                default:
                    context.Claims[kvp.Key] = kvp.Value?.ToString();
                    break;
            }
        }
    }

    // === Logic ported from legacy UserInfoHandler ===
    private async Task<List<IdentityResource>> GetIdentityResourcesForScopesAsync(IEnumerable<string> scopes)
    {
        var set = scopes.Select(s => s.Trim()).ToHashSet(StringComparer.OrdinalIgnoreCase);
        if (set.Count == 0) {
            return new();
        }

        return await _db.IdentityResources
            .Include(r => r.UserClaims)
            .Where(r => r.IsEnabled && set.Contains(r.Name))
            .ToListAsync();
    }

    private async Task<Dictionary<string, object>> BuildUserInfoAsync(IdentityUser user, List<IdentityResource> idResources, IEnumerable<string> scopes)
    {
        var dict = new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase)
        {
            ["sub"] = user.Id
        };
        if (idResources.Count == 0) {
            return dict;
        }

        var claims = await _userManager.GetClaimsAsync(user);
        var lookup = claims.GroupBy(c => c.Type, StringComparer.OrdinalIgnoreCase).ToDictionary(g => g.Key, g => g.First().Value, StringComparer.OrdinalIgnoreCase);
        foreach (var res in idResources)
        {
            foreach (var uc in res.UserClaims)
            {
                if (dict.ContainsKey(uc.ClaimType)) {
                    continue;
                }

                if (lookup.TryGetValue(uc.ClaimType, out var val) && !string.IsNullOrWhiteSpace(val))
                {
                    dict[uc.ClaimType] = val;
                }
            }
        }
        return dict;
    }

    private async Task AddMissingStandardScopeClaimsAsync(Dictionary<string, object> userInfo, IdentityUser user, IEnumerable<string> scopes, bool onlyIfMissing)
    {
        foreach (var scope in scopes)
        {
            await AddClaimsForScope(userInfo, user, scope, onlyIfMissing);
        }
    }

    private async Task AddClaimsForScope(Dictionary<string, object> userInfo, IdentityUser user, string scope, bool onlyIfMissing)
    {
        async Task Add(string type)
        {
            if (onlyIfMissing && userInfo.ContainsKey(type)) {
                return;
            }

            await AddClaimIfPresent(userInfo, user, type);
        }
        switch (scope.ToLowerInvariant())
        {
            case "profile":
                await Add("name"); await Add("given_name"); await Add("family_name"); await Add("preferred_username"); await Add("picture"); await Add("website"); await Add("gender"); await Add("birthdate"); await Add("zoneinfo"); await Add("locale"); await Add("updated_at");
                break;
            case "email": await Add("email"); await Add("email_verified"); break;
            case "phone": await Add("phone_number"); await Add("phone_number_verified"); break;
            case "roles":
                if (!userInfo.ContainsKey("role"))
                {
                    var roles = await GetRolesAsync(user);
                    if (roles.Length > 0) {
                        userInfo["role"] = roles;
                    }
                }
                break;
            case "address": await Add("address"); break;
        }
    }

    private async Task AddClaimIfPresent(Dictionary<string, object> userInfo, IdentityUser user, string type)
    {
        if (userInfo.ContainsKey(type)) {
            return;
        }

        var val = await GetClaimValueAsync(user, type);
        if (val == null) {
            return;
        }

        userInfo[type] = val is bool b ? b : val;
    }

    private async Task<object?> GetClaimValueAsync(IdentityUser user, string type) => type switch
    {
        "sub" => user.Id,
        "email" => user.Email,
        "email_verified" => user.EmailConfirmed,
        "preferred_username" => $"{user.UserName}",
        "phone_number" => user.PhoneNumber,
        "phone_number_verified" => user.PhoneNumberConfirmed,
        "name" => await GetUserClaimValueAsync(user, "name") ?? GetDisplayName(user),
        "role" => await GetRolesAsync(user),
        _ => await GetUserClaimValueAsync(user, type)
    };

    private async Task<string?> GetUserClaimValueAsync(IdentityUser user, string type)
    {
        try
        {
            var claims = await _userManager.GetClaimsAsync(user);
            return claims.FirstOrDefault(c => c.Type.Equals(type, StringComparison.OrdinalIgnoreCase))?.Value;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error reading claim {Type} for user {UserId}", type, user.Id);
            return null;
        }
    }

    private async Task<string[]> GetRolesAsync(IdentityUser user)
    {
        try { return (await _userManager.GetRolesAsync(user)).ToArray(); }
        catch (Exception ex) { _logger.LogError(ex, "Error retrieving roles for user {UserId}", user.Id); return Array.Empty<string>(); }
    }

    private string GetDisplayName(IdentityUser user)
    {
        if (string.IsNullOrWhiteSpace(user.UserName)) {
            return "Unknown User";
        }

        var input = user.UserName.Contains('@') ? user.UserName.Split('@')[0] : user.UserName;
        var friendly = input.Replace('.', ' ').Replace('_', ' ').Replace('-', ' ');
        return string.Join(" ", friendly.Split(' ', StringSplitOptions.RemoveEmptyEntries).Select(w => char.ToUpper(w[0]) + w[1..].ToLower()));
    }
}