using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Authentication;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using System.Security.Claims;
using Microsoft.AspNetCore.Http.Extensions;
using MrWho.Data;
using Microsoft.EntityFrameworkCore;
using MrWho.Models;
using Microsoft.AspNetCore; // OpenIddict extension visibility

namespace MrWho.Handlers;

public interface IOidcAuthorizationHandler
{
    Task<IResult> HandleAuthorizationRequestAsync(HttpContext context);
}

public class OidcAuthorizationHandler : IOidcAuthorizationHandler
{
    private readonly UserManager<IdentityUser> _userManager;
    private readonly ApplicationDbContext _context;
    private readonly ILogger<OidcAuthorizationHandler> _logger;

    public OidcAuthorizationHandler(UserManager<IdentityUser> userManager,
                                    ApplicationDbContext context,
                                    ILogger<OidcAuthorizationHandler> logger)
    {
        _userManager = userManager;
        _context = context;
        _logger = logger;
    }

    public async Task<IResult> HandleAuthorizationRequestAsync(HttpContext context)
    {
        var request = context.GetOpenIddictServerRequest() ?? throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");
        var clientId = request.ClientId ?? string.Empty;
        _logger.LogDebug("Authorization request received for client {ClientId}", clientId);

        // Early scope validation
        try
        {
            var requestedScopes = request.GetScopes().ToList();
            if (!string.IsNullOrWhiteSpace(clientId) && requestedScopes.Count > 0)
            {
                var dbClient = await _context.Clients.AsNoTracking().Include(c => c.Scopes).FirstOrDefaultAsync(c => c.ClientId == clientId);
                if (dbClient != null)
                {
                    var allowed = dbClient.Scopes.Select(s => s.Scope).ToHashSet(StringComparer.OrdinalIgnoreCase);
                    var missing = requestedScopes.Where(s => !allowed.Contains(s)).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
                    if (missing.Count > 0)
                    {
                        var currentUrl = context.Request.GetDisplayUrl();
                        var url = "/connect/invalid-scopes?clientId=" + Uri.EscapeDataString(clientId) +
                                  "&returnUrl=" + Uri.EscapeDataString(currentUrl) +
                                  "&missing=" + Uri.EscapeDataString(string.Join(" ", missing)) +
                                  "&requested=" + Uri.EscapeDataString(string.Join(" ", requestedScopes));
                        return Results.Redirect(url);
                    }
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Early scope validation failed for client {ClientId}", clientId);
        }

        IdentityUser? authUser = null;
        ClaimsPrincipal? amrSource = null;

        try
        {
            var defaultAuth = await context.AuthenticateAsync(IdentityConstants.ApplicationScheme);
            if (defaultAuth.Succeeded && defaultAuth.Principal?.Identity?.IsAuthenticated == true)
            {
                var subj = defaultAuth.Principal.FindFirst(ClaimTypes.NameIdentifier);
                subj ??= defaultAuth.Principal.FindFirst(OpenIddictConstants.Claims.Subject);
                subj ??= defaultAuth.Principal.FindFirst("sub");
                if (subj != null)
                {
                    var user = await _userManager.FindByIdAsync(subj.Value);
                    if (user != null)
                    {
                        authUser = user;
                        amrSource = defaultAuth.Principal;
                    }
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Default cookie authentication failed for client {ClientId}", clientId);
        }

        if (authUser == null)
        {
            var props = new AuthenticationProperties { RedirectUri = context.Request.GetDisplayUrl() };
            return Results.Challenge(props, new[] { IdentityConstants.ApplicationScheme });
        }

        // Basic profile activity check
        try
        {
            var profile = await _context.UserProfiles.AsNoTracking().FirstOrDefaultAsync(p => p.UserId == authUser.Id);
            if (profile == null || profile.State != UserState.Active)
            {
                _logger.LogInformation("Inactive/missing profile for user {UserId}", authUser.Id);
                return Results.Redirect(BuildAccessDeniedUrl(context, clientId));
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Profile lookup failed for user {UserId}", authUser.Id);
        }

        var id = new ClaimsIdentity(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        void Add(string type, string value)
        {
            var c = new Claim(type, value);
            c.SetDestinations(OpenIddictConstants.Destinations.AccessToken, OpenIddictConstants.Destinations.IdentityToken);
            id.AddClaim(c);
        }
        Add(OpenIddictConstants.Claims.Subject, authUser.Id);
        Add(OpenIddictConstants.Claims.Email, authUser.Email ?? string.Empty);
        Add(OpenIddictConstants.Claims.Name, await GetUserNameClaimAsync(authUser));
        Add(OpenIddictConstants.Claims.PreferredUsername, authUser.UserName ?? string.Empty);

        await AddProfileClaimsAsync(id, authUser, request.GetScopes());
        foreach (var r in await _userManager.GetRolesAsync(authUser)) Add(OpenIddictConstants.Claims.Role, r);

        try
        {
            foreach (var amr in amrSource?.FindAll("amr") ?? Array.Empty<Claim>()) Add("amr", amr.Value);
        }
        catch { }

        var principal = new ClaimsPrincipal(id);
        principal.SetScopes(request.GetScopes());
        return Results.SignIn(principal, authenticationScheme: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }

    private static string BuildAccessDeniedUrl(HttpContext context, string clientId)
    {
        var currentUrl = context.Request.GetDisplayUrl();
        var returnUrl = Uri.EscapeDataString(currentUrl);
        var cid = Uri.EscapeDataString(clientId ?? string.Empty);
        var url = $"/connect/access-denied?returnUrl={returnUrl}";
        if (!string.IsNullOrEmpty(cid)) url += $"&clientId={cid}";
        return url;
    }

    private async Task<string> GetUserNameClaimAsync(IdentityUser user)
    {
        try
        {
            var claims = await _userManager.GetClaimsAsync(user);
            var nameClaim = claims.FirstOrDefault(c => c.Type == "name")?.Value;
            if (!string.IsNullOrEmpty(nameClaim)) return nameClaim;
        }
        catch { }
        return ConvertToFriendlyName(user.UserName ?? "Unknown User");
    }

    private async Task AddProfileClaimsAsync(ClaimsIdentity identity, IdentityUser user, IEnumerable<string> scopes)
    {
        try
        {
            if (!scopes.Contains(OpenIddictConstants.Scopes.Profile)) return;
            var claims = await _userManager.GetClaimsAsync(user);
            void Maybe(string src, string target)
            {
                var v = claims.FirstOrDefault(c => c.Type == src)?.Value;
                if (!string.IsNullOrEmpty(v))
                {
                    var c = new Claim(target, v);
                    c.SetDestinations(OpenIddictConstants.Destinations.AccessToken, OpenIddictConstants.Destinations.IdentityToken);
                    identity.AddClaim(c);
                }
            }
            Maybe("given_name", OpenIddictConstants.Claims.GivenName);
            Maybe("family_name", OpenIddictConstants.Claims.FamilyName);
            Maybe("picture", OpenIddictConstants.Claims.Picture);
        }
        catch { }
    }

    private string ConvertToFriendlyName(string input)
    {
        if (string.IsNullOrWhiteSpace(input)) return "Unknown User";
        if (input.Contains('@')) input = input.Split('@')[0];
        var friendly = input.Replace('.', ' ').Replace('_', ' ').Replace('-', ' ');
        return string.Join(" ", friendly.Split(' ', StringSplitOptions.RemoveEmptyEntries).Select(w => char.ToUpper(w[0]) + w[1..].ToLower()));
    }
}