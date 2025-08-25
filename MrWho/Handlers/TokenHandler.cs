using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using System.Security.Claims;
using Microsoft.EntityFrameworkCore;
using MrWho.Data;
using MrWho.Services;
using MrWho.Shared;

namespace MrWho.Handlers;

public interface ITokenHandler
{
    Task<IResult> HandleTokenRequestAsync(HttpContext context);
}

public class TokenHandler : ITokenHandler
{
    private readonly UserManager<IdentityUser> _userManager;
    private readonly ApplicationDbContext _db;
    private readonly IClientRoleService _clientRoleService;
    private readonly ILogger<TokenHandler> _logger;

    public TokenHandler(UserManager<IdentityUser> userManager,
                        ApplicationDbContext db,
                        IClientRoleService clientRoleService,
                        ILogger<TokenHandler> logger)
    {
        _userManager = userManager;
        _db = db;
        _clientRoleService = clientRoleService;
        _logger = logger;
    }

    // Acquire OpenIddict request from HTTP context (works without extension method)
    private OpenIddictRequest GetRequest(HttpContext context)
    {
        var feature = context.Features.Get<OpenIddictServerAspNetCoreFeature>();
        if (feature?.Transaction?.Request != null) return feature.Transaction.Request;
        throw new InvalidOperationException("OIDC request unavailable.");
    }

    public async Task<IResult> HandleTokenRequestAsync(HttpContext context)
    {
        var request = GetRequest(context);
        _logger.LogDebug("Token request: grant={GrantType} client={ClientId}", request.GrantType, request.ClientId);
        if (request.IsPasswordGrantType()) return await HandlePasswordGrantAsync(request);
        if (request.IsClientCredentialsGrantType()) return await HandleClientCredentialsGrantAsync(request);
        if (request.IsAuthorizationCodeGrantType()) return await HandleAuthorizationCodeGrantAsync(context, request);
        if (request.IsRefreshTokenGrantType()) return await HandleRefreshTokenGrantAsync(context, request);
        throw new InvalidOperationException($"Unsupported grant type '{request.GrantType}'.");
    }

    // ----------------------- ROLE INCLUSION -----------------------
    private RoleInclusion ResolveRoleInclusion(IEnumerable<string> scopes)
    {
        var set = scopes.ToHashSet(StringComparer.OrdinalIgnoreCase);
        if (set.Contains("roles.all") || (set.Contains("roles.global") && set.Contains("roles.client"))) return RoleInclusion.GlobalAndClient;
        if (set.Contains("roles.client")) return RoleInclusion.ClientOnly;
        if (set.Contains("roles.global")) return RoleInclusion.GlobalOnly;
        if (set.Contains(OpenIddictConstants.Scopes.Roles)) return RoleInclusion.GlobalAndClient; // standard roles scope
        return RoleInclusion.GlobalOnly; // default least privilege
    }

    private async Task AddRolesAsync(ClaimsIdentity identity, IdentityUser user, string clientId, IEnumerable<string> scopes)
    {
        var client = await _db.Clients.AsNoTracking().FirstOrDefaultAsync(c => c.ClientId == clientId);
        var inclusion = client?.RoleInclusionOverride switch
        {
            ClientRoleInclusionOverride.GlobalOnly => RoleInclusion.GlobalOnly,
            ClientRoleInclusionOverride.ClientOnly => RoleInclusion.ClientOnly,
            ClientRoleInclusionOverride.GlobalAndClient => RoleInclusion.GlobalAndClient,
            _ => ResolveRoleInclusion(scopes)
        };

        // Global roles
        if (inclusion is RoleInclusion.GlobalOnly or RoleInclusion.GlobalAndClient || scopes.Contains(OpenIddictConstants.Scopes.Roles))
        {
            var globalRoles = await _userManager.GetRolesAsync(user);
            foreach (var r in globalRoles)
                AddClaim(identity, OpenIddictConstants.Claims.Role, r);
        }
        // Client scoped roles
        if (inclusion is RoleInclusion.ClientOnly or RoleInclusion.GlobalAndClient)
        {
            var clientRoles = await _clientRoleService.GetClientRolesAsync(user.Id, clientId);
            foreach (var r in clientRoles)
            {
                AddClaim(identity, OpenIddictConstants.Claims.Role, r);
                AddClaim(identity, "client_role", r);
            }
        }
    }

    // ----------------------- PASSWORD GRANT -----------------------
    private async Task<IResult> HandlePasswordGrantAsync(OpenIddictRequest request)
    {
        var user = await _userManager.FindByNameAsync(request.Username!) ?? await _userManager.FindByEmailAsync(request.Username!);
        if (user == null || !await _userManager.CheckPasswordAsync(user, request.Password!))
            return InvalidGrant("Invalid username or password.");

        var id = BuildBaseIdentity(user);
        await AddProfileClaimsAsync(id, user, request.GetScopes());
        await AddRolesAsync(id, user, request.ClientId!, request.GetScopes());

        var principal = new ClaimsPrincipal(id);
        principal.SetScopes(request.GetScopes());
        var aud = await ApplyAudiencesAsync(principal, request.ClientId!, request.GetScopes());
        if (aud.Error) return InvalidScope(aud.Description);
        return Results.SignIn(principal, authenticationScheme: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }

    private async Task<IResult> HandleClientCredentialsGrantAsync(OpenIddictRequest request)
    {
        var id = new ClaimsIdentity(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        AddClaim(id, OpenIddictConstants.Claims.Subject, request.ClientId!, onlyAccessToken: true);
        var principal = new ClaimsPrincipal(id);
        principal.SetScopes(request.GetScopes());
        var aud = await ApplyAudiencesAsync(principal, request.ClientId!, request.GetScopes());
        if (aud.Error) return InvalidScope(aud.Description);
        return Results.SignIn(principal, authenticationScheme: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }

    private async Task<IResult> HandleAuthorizationCodeGrantAsync(HttpContext context, OpenIddictRequest request)
    {
        var authenticateResult = await context.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        var principal = authenticateResult.Principal;
        if (principal == null) return Results.Forbid(authenticationSchemes: new[] { OpenIddictServerAspNetCoreDefaults.AuthenticationScheme });

        var userId = principal.FindFirst(OpenIddictConstants.Claims.Subject)?.Value;
        var id = new ClaimsIdentity(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        foreach (var t in new[] { OpenIddictConstants.Claims.Subject, OpenIddictConstants.Claims.Name, OpenIddictConstants.Claims.Email, OpenIddictConstants.Claims.PreferredUsername, OpenIddictConstants.Claims.GivenName, OpenIddictConstants.Claims.FamilyName })
        {
            var c = principal.FindFirst(t);
            if (c != null) AddClaim(id, c.Type, c.Value);
        }
        if (!string.IsNullOrEmpty(userId))
        {
            var user = await _userManager.FindByIdAsync(userId);
            if (user != null)
                await AddRolesAsync(id, user, request.ClientId!, request.GetScopes());
        }
        var newPrincipal = new ClaimsPrincipal(id);
        newPrincipal.SetScopes(request.GetScopes());
        var aud = await ApplyAudiencesAsync(newPrincipal, request.ClientId!, request.GetScopes());
        if (aud.Error) return InvalidScope(aud.Description);
        return Results.SignIn(newPrincipal, authenticationScheme: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }

    private async Task<IResult> HandleRefreshTokenGrantAsync(HttpContext context, OpenIddictRequest request)
    {
        var authenticateResult = await context.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        var principal = authenticateResult.Principal;
        if (principal == null) return Results.Forbid(authenticationSchemes: new[] { OpenIddictServerAspNetCoreDefaults.AuthenticationScheme });

        var subject = principal.FindFirst(OpenIddictConstants.Claims.Subject)?.Value;
        if (string.IsNullOrEmpty(subject)) return Results.Forbid(authenticationSchemes: new[] { OpenIddictServerAspNetCoreDefaults.AuthenticationScheme });
        var user = await _userManager.FindByIdAsync(subject);
        if (user == null) return Results.Forbid(authenticationSchemes: new[] { OpenIddictServerAspNetCoreDefaults.AuthenticationScheme });
        if (!user.EmailConfirmed && _userManager.Options.SignIn.RequireConfirmedEmail)
            return Results.Forbid(authenticationSchemes: new[] { OpenIddictServerAspNetCoreDefaults.AuthenticationScheme });

        var id = BuildBaseIdentity(user);
        await AddProfileClaimsAsync(id, user, request.GetScopes());
        await AddRolesAsync(id, user, request.ClientId!, request.GetScopes());
        var newPrincipal = new ClaimsPrincipal(id);
        newPrincipal.SetScopes(request.GetScopes());
        var aud = await ApplyAudiencesAsync(newPrincipal, request.ClientId!, request.GetScopes());
        if (aud.Error) return InvalidScope(aud.Description);
        return Results.SignIn(newPrincipal, authenticationScheme: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }

    // ----------------------- HELPERS -----------------------
    private ClaimsIdentity BuildBaseIdentity(IdentityUser user)
    {
        var id = new ClaimsIdentity(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        AddClaim(id, OpenIddictConstants.Claims.Subject, user.Id);
        AddClaim(id, OpenIddictConstants.Claims.Email, user.Email ?? string.Empty);
        var display = user.UserName ?? user.Email ?? user.Id;
        AddClaim(id, OpenIddictConstants.Claims.Name, ConvertToFriendlyName(display));
        AddClaim(id, OpenIddictConstants.Claims.PreferredUsername, user.UserName ?? display);
        return id;
    }

    private void AddClaim(ClaimsIdentity id, string type, string value, bool onlyAccessToken = false)
    {
        var c = new Claim(type, value);
        c.SetDestinations(onlyAccessToken ? new[] { OpenIddictConstants.Destinations.AccessToken } : new[] { OpenIddictConstants.Destinations.AccessToken, OpenIddictConstants.Destinations.IdentityToken });
        id.AddClaim(c);
    }

    private async Task AddProfileClaimsAsync(ClaimsIdentity id, IdentityUser user, IEnumerable<string> scopes)
    {
        try
        {
            if (!scopes.Contains(OpenIddictConstants.Scopes.Profile)) return;
            var claims = await _userManager.GetClaimsAsync(user);
            void Maybe(string src, string target)
            {
                var v = claims.FirstOrDefault(c => c.Type == src)?.Value;
                if (!string.IsNullOrEmpty(v)) AddClaim(id, target, v);
            }
            Maybe("given_name", OpenIddictConstants.Claims.GivenName);
            Maybe("family_name", OpenIddictConstants.Claims.FamilyName);
            Maybe("picture", OpenIddictConstants.Claims.Picture);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Profile claims retrieval failed for user {UserId}", user.Id);
        }
    }

    private string ConvertToFriendlyName(string input)
    {
        if (string.IsNullOrWhiteSpace(input)) return "Unknown User";
        if (input.Contains('@')) input = input.Split('@')[0];
        var friendly = input.Replace('.', ' ').Replace('_', ' ').Replace('-', ' ');
        return string.Join(" ", friendly.Split(' ', StringSplitOptions.RemoveEmptyEntries).Select(w => char.ToUpper(w[0]) + w[1..].ToLower()));
    }

    private sealed record AudienceApplyResult(bool Error, string? Description = null);

    private async Task<AudienceApplyResult> ApplyAudiencesAsync(ClaimsPrincipal principal, string clientId, IEnumerable<string> requestedScopes)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(clientId)) return new(false);
            var scopeSet = requestedScopes.ToHashSet(StringComparer.OrdinalIgnoreCase);
            var client = await _db.Clients.Include(c => c.Audiences).Include(c => c.Realm).FirstOrDefaultAsync(c => c.ClientId == clientId);
            if (client == null) return new(false);
            var mode = client.AudienceMode ?? client.Realm?.AudienceMode ?? AudienceMode.RequestedIntersection;
            var includeInId = client.IncludeAudInIdToken ?? client.Realm?.IncludeAudInIdToken ?? true;
            var explicitRequired = client.RequireExplicitAudienceScope ?? client.Realm?.RequireExplicitAudienceScope ?? false;
            var primary = client.PrimaryAudience ?? client.Realm?.PrimaryAudience;
            var configured = client.Audiences.Select(a => a.Audience).Where(a => !string.IsNullOrWhiteSpace(a)).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
            if (configured.Count == 0 || mode == AudienceMode.None) return new(false);
            var intersection = configured.Where(scopeSet.Contains).ToList();
            List<string> result = new();
            switch (mode)
            {
                case AudienceMode.RequestedIntersection: result = intersection; break;
                case AudienceMode.AllConfigured: result = configured; break;
                case AudienceMode.RequestedOrAll: result = intersection.Count > 0 ? intersection : configured; break;
                case AudienceMode.RequestedOrPrimary:
                    if (intersection.Count > 0) result = intersection;
                    else if (!string.IsNullOrWhiteSpace(primary) && configured.Contains(primary, StringComparer.OrdinalIgnoreCase)) result = new() { primary! };
                    else result = new() { configured.First() }; break;
                case AudienceMode.ErrorIfUnrequested:
                    if (intersection.Count == 0) return new(true, "Required audience scope missing");
                    result = intersection; break;
                case AudienceMode.AccessTokenOnly: result = intersection; break;
            }
            if (explicitRequired && intersection.Count == 0 && mode != AudienceMode.AllConfigured) return new(true, "Explicit audience scope required");
            if (result.Count == 0 || principal.HasClaim(c => c.Type == OpenIddictConstants.Claims.Audience)) return new(false);
            foreach (var aud in result.Distinct())
            {
                var claim = new Claim(OpenIddictConstants.Claims.Audience, aud);
                if (mode == AudienceMode.AccessTokenOnly || !includeInId)
                    claim.SetDestinations(OpenIddictConstants.Destinations.AccessToken);
                else
                    claim.SetDestinations(OpenIddictConstants.Destinations.AccessToken, OpenIddictConstants.Destinations.IdentityToken);
                (principal.Identity as ClaimsIdentity)!.AddClaim(claim);
            }
            return new(false);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to apply audiences for client {ClientId}", clientId);
            return new(false);
        }
    }

    // ----------------------- ERROR HELPERS -----------------------
    private IResult InvalidGrant(string description) => Results.Forbid(new AuthenticationProperties(new Dictionary<string, string?>
    {
        [OpenIddictServerAspNetCoreConstants.Properties.Error] = OpenIddictConstants.Errors.InvalidGrant,
        [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = description
    }), new[] { OpenIddictServerAspNetCoreDefaults.AuthenticationScheme });

    private IResult InvalidScope(string? description) => Results.Forbid(new AuthenticationProperties(new Dictionary<string, string?>
    {
        [OpenIddictServerAspNetCoreConstants.Properties.Error] = OpenIddictConstants.Errors.InvalidScope,
        [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = description ?? "Invalid or missing scope"
    }), new[] { OpenIddictServerAspNetCoreDefaults.AuthenticationScheme });
}