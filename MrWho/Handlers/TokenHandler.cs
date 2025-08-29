using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Authentication;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using System.Security.Claims;
using Microsoft.AspNetCore;
using MrWho.Services;
using MrWho.Data; // add db
using Microsoft.EntityFrameworkCore; // include for Include
using MrWho.Shared; // for AudienceMode
using static OpenIddict.Abstractions.OpenIddictConstants;
using MrWho.Models; // for Destinations & claims

namespace MrWho.Handlers;

public interface ITokenHandler
{
    Task<IResult> HandleTokenRequestAsync(HttpContext context);
}

public class TokenHandler : ITokenHandler
{
    private readonly UserManager<IdentityUser> _userManager;
    private readonly SignInManager<IdentityUser> _signInManager;
    private readonly IClientCookieConfigurationService _cookieService;
    private readonly IUserRealmValidationService _realmValidationService;
    private readonly ILogger<TokenHandler> _logger;
    private readonly ApplicationDbContext _db;
    private readonly IClientRoleService _clientRoleService;

    public TokenHandler(
        UserManager<IdentityUser> userManager,
        SignInManager<IdentityUser> signInManager,
        IClientCookieConfigurationService cookieService,
        IUserRealmValidationService realmValidationService,
        ILogger<TokenHandler> logger,
        ApplicationDbContext db,
        IClientRoleService clientRoleService)
    {
        _userManager = userManager;
        _signInManager = signInManager;
        _cookieService = cookieService;
        _realmValidationService = realmValidationService;
        _logger = logger;
        _db = db;
        _clientRoleService = clientRoleService;
    }

    public async Task<IResult> HandleTokenRequestAsync(HttpContext context)
    {
        var request = context.GetOpenIddictServerRequest() ??
                      throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

        // Log the grant type for debugging
        _logger.LogDebug("Token request received: GrantType={GrantType}, ClientId={ClientId}", 
            request.GrantType, request.ClientId);

        if (request.IsPasswordGrantType())
        {
            return await HandlePasswordGrantAsync(context, request);
        }

        if (request.IsClientCredentialsGrantType())
        {
            return await HandleClientCredentialsGrantAsync(request);
        }

        if (request.IsAuthorizationCodeGrantType())
        {
            return await HandleAuthorizationCodeGrantAsync(context, request);
        }

        if (request.IsRefreshTokenGrantType())
        {
            return await HandleRefreshTokenGrantAsync(context, request);
        }

        throw new InvalidOperationException($"The specified grant type '{request.GrantType}' is not supported.");
    }

    // --- helper to build a fresh user identity consistently across flows ---
    private async Task<ClaimsIdentity> BuildUserIdentityAsync(IdentityUser user, string clientId, IEnumerable<string> scopes)
    {
        // Load client to respect AlwaysIncludeUserClaimsInIdToken flag
        var client = await _db.Clients.FirstOrDefaultAsync(c => c.ClientId == clientId);
        var includeInId = client?.AlwaysIncludeUserClaimsInIdToken == true; // default false if null

        string[] destinations = includeInId
            ? new[] { Destinations.AccessToken, Destinations.IdentityToken }
            : new[] { Destinations.AccessToken }; // userinfo-only exposure for privacy


        var identity = new ClaimsIdentity(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);

        // Core user claims
        var subClaim = new Claim(OpenIddictConstants.Claims.Subject, user.Id);
        subClaim.SetDestinations(Destinations.AccessToken, Destinations.IdentityToken);
        identity.AddClaim(subClaim);

        if (!string.IsNullOrWhiteSpace(user.Email))
        {
            var emailClaim = new Claim(OpenIddictConstants.Claims.Email, user.Email);
            emailClaim.SetDestinations(destinations);
            identity.AddClaim(emailClaim);
        }

        // Display/name claims
        var display = await GetUserNameClaimAsync(user);
        var nameClaim = new Claim(OpenIddictConstants.Claims.Name, display);
        nameClaim.SetDestinations(destinations);
        identity.AddClaim(nameClaim);

        if (!string.IsNullOrWhiteSpace(user.UserName))
        {
            var preferredUsernameClaim = new Claim(OpenIddictConstants.Claims.PreferredUsername, user.UserName);
            preferredUsernameClaim.SetDestinations(destinations);
            identity.AddClaim(preferredUsernameClaim);
        }

        // Profile (given/family/picture ...) if profile scope
        await AddProfileClaimsAsync(identity, user, scopes, client);
        // Identity resource claims (AccessToken only unless AlwaysIncludeUserClaimsInIdToken)
        await AddIdentityResourceClaimsAsync(identity, user, scopes, client);
        // Roles (global + client)
        await AddRolesAsync(identity, user, clientId, scopes);
        return identity;
    }

    private RoleInclusion ResolveRoleInclusion(IEnumerable<string> scopes)
    {
        var set = scopes.ToHashSet(StringComparer.OrdinalIgnoreCase);
        if (set.Contains("roles.all") || (set.Contains("roles.global") && set.Contains("roles.client")))
            return RoleInclusion.GlobalAndClient;
        if (set.Contains("roles.client")) return RoleInclusion.ClientOnly;
        if (set.Contains("roles.global")) return RoleInclusion.GlobalOnly;
        if (set.Contains(Scopes.Roles)) return RoleInclusion.GlobalAndClient;
        return RoleInclusion.GlobalOnly;
    }

    private async Task AddRolesAsync(ClaimsIdentity identity, IdentityUser user, string clientId, IEnumerable<string> scopes)
    {
        // Load client once to inspect override
        var client = await _db.Clients.FirstOrDefaultAsync(c => c.ClientId == clientId);
        RoleInclusion inclusion;
        if (client?.RoleInclusionOverride != null)
        {
            inclusion = client.RoleInclusionOverride.Value switch
            {
                ClientRoleInclusionOverride.GlobalOnly => RoleInclusion.GlobalOnly,
                ClientRoleInclusionOverride.ClientOnly => RoleInclusion.ClientOnly,
                ClientRoleInclusionOverride.GlobalAndClient => RoleInclusion.GlobalAndClient,
                _ => ResolveRoleInclusion(scopes)
            };
        }
        else
        {
            inclusion = ResolveRoleInclusion(scopes);
        }
        if (inclusion == RoleInclusion.GlobalOnly || inclusion == RoleInclusion.GlobalAndClient || scopes.Contains(Scopes.Roles))
        {
            var globalRoles = await _userManager.GetRolesAsync(user);
            foreach (var role in globalRoles)
            {
                var roleClaim = new Claim(Claims.Role, role);
                roleClaim.SetDestinations(Destinations.AccessToken, Destinations.IdentityToken);
                identity.AddClaim(roleClaim);
            }
        }
        if (inclusion == RoleInclusion.ClientOnly || inclusion == RoleInclusion.GlobalAndClient)
        {
            var clientRoles = await _clientRoleService.GetClientRolesAsync(user.Id, clientId);
            foreach (var role in clientRoles)
            {
                var roleClaim = new Claim(Claims.Role, role);
                roleClaim.SetDestinations(Destinations.AccessToken, Destinations.IdentityToken);
                identity.AddClaim(roleClaim);
                var crClaim = new Claim("client_role", role);
                crClaim.SetDestinations(Destinations.AccessToken, Destinations.IdentityToken);
                identity.AddClaim(crClaim);
            }
        }
    }

    // NEW: Add claims defined by enabled IdentityResources matching requested scopes
    private async Task AddIdentityResourceClaimsAsync(ClaimsIdentity identity, IdentityUser user, IEnumerable<string> scopes, Client? client)
    {
        try
        {
            var scopeSet = scopes.ToHashSet(StringComparer.OrdinalIgnoreCase);
            // Fetch enabled identity resources whose names were requested
            var idResources = await _db.IdentityResources
                .Include(r => r.UserClaims)
                .Where(r => r.IsEnabled && scopeSet.Contains(r.Name))
                .ToListAsync();
            if (idResources.Count == 0) return;

            // Load client to respect AlwaysIncludeUserClaimsInIdToken flag
            var includeInId = client?.AlwaysIncludeUserClaimsInIdToken == true; // default false if null

            var userClaims = await _userManager.GetClaimsAsync(user);
            var userClaimLookup = userClaims.GroupBy(c => c.Type)
                                            .ToDictionary(g => g.Key, g => g.First().Value, StringComparer.OrdinalIgnoreCase);
            var existingTypes = identity.Claims.Select(c => c.Type).ToHashSet(StringComparer.OrdinalIgnoreCase);

            foreach (var claimType in idResources.SelectMany(r => r.UserClaims.Select(uc => uc.ClaimType)).Distinct(StringComparer.OrdinalIgnoreCase))
            {
                if (existingTypes.Contains(claimType)) continue; // already added elsewhere (e.g., sub, email, name)
                if (!userClaimLookup.TryGetValue(claimType, out var value) || string.IsNullOrWhiteSpace(value)) continue;

                var claim = new Claim(claimType, value);
                if (includeInId)
                {
                    claim.SetDestinations(Destinations.AccessToken, Destinations.IdentityToken);
                }
                else
                {
                    claim.SetDestinations(Destinations.AccessToken); // userinfo-only exposure for privacy
                }
                identity.AddClaim(claim);
                existingTypes.Add(claimType);
            }

            _logger.LogDebug("Added {Count} identity resource claims for user {UserId} (IncludeInId={Include})", idResources.Sum(r => r.UserClaims.Count), user.Id, includeInId);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed adding identity resource claims for user {UserId}", user.Id);
        }
    }

    private async Task<IResult> HandlePasswordGrantAsync(HttpContext context, OpenIddictRequest request)
    {
        var user = await _userManager.FindByNameAsync(request.Username!);

        if (user == null || !await _userManager.CheckPasswordAsync(user, request.Password!))
        {
            var propertiesInvalid = new AuthenticationProperties(new Dictionary<string, string?>
            {
                [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
                [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "The username/password couple is invalid."
            });
            return Results.Forbid(propertiesInvalid, new[] { OpenIddictServerAspNetCoreDefaults.AuthenticationScheme });
        }

        var clientId = request.ClientId!;
        
        // CRITICAL: Validate user can access this client based on realm restrictions
        var realmValidation = await _realmValidationService.ValidateUserRealmAccessAsync(user, clientId);
        if (!realmValidation.IsValid)
        {
            _logger.LogWarning("User {UserName} denied access to client {ClientId} via password grant: {Reason}", 
                user.UserName, clientId, realmValidation.Reason);
            
            var forbidProperties = new AuthenticationProperties(new Dictionary<string, string?>
            {
                [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.AccessDenied,
                [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = realmValidation.Reason ?? "User does not have access to this client"
            });

            return Results.Forbid(forbidProperties, new[] { OpenIddictServerAspNetCoreDefaults.AuthenticationScheme });
        }

        _logger.LogInformation("User {UserName} validated for password grant access to client {ClientId} in realm {Realm}", 
            user.UserName, clientId, realmValidation.ClientRealm);

        var scopes = request.GetScopes();
        var identity = await BuildUserIdentityAsync(user, clientId, scopes);
        var principal = new ClaimsPrincipal(identity);
        principal.SetScopes(scopes);
        var audienceResult = await ApplyAudiencesAsync(principal, clientId, scopes, context);
        if (audienceResult.Error)
        {
            var forbidProps = new AuthenticationProperties(new Dictionary<string, string?>
            {
                [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidScope,
                [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = audienceResult.Description ?? "Required audience scope not requested"
            });
            return Results.Forbid(forbidProps, new[] { OpenIddictServerAspNetCoreDefaults.AuthenticationScheme });
        }

        // Try persisting session
        var cookieScheme = _cookieService.GetCookieSchemeForClient(clientId);
        try
        {
            await context.SignInAsync(cookieScheme, principal);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Cookie sign-in failed for scheme {Scheme}", cookieScheme);
        }

        return Results.SignIn(principal, authenticationScheme: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }

    private async Task<IResult> HandleClientCredentialsGrantAsync(OpenIddictRequest request)
    {
        var identity = new ClaimsIdentity(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        var subClaim = new Claim(Claims.Subject, request.ClientId!);
        subClaim.SetDestinations(Destinations.AccessToken);
        identity.AddClaim(subClaim);

        var principal = new ClaimsPrincipal(identity);
        principal.SetScopes(request.GetScopes());
        var audienceResult = await ApplyAudiencesAsync(principal, request.ClientId!, request.GetScopes(), null);
        if (audienceResult.Error)
        {
            var forbidProps = new AuthenticationProperties(new Dictionary<string, string?>
            {
                [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidScope,
                [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = audienceResult.Description ?? "Required audience scope not requested"
            });
            return Results.Forbid(forbidProps, new[] { OpenIddictServerAspNetCoreDefaults.AuthenticationScheme });
        }
        return Results.SignIn(principal, authenticationScheme: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }

    private async Task<IResult> HandleAuthorizationCodeGrantAsync(HttpContext context, OpenIddictRequest request)
    {
        var clientId = request.ClientId!;
        ClaimsPrincipal? authPrincipal = null;
        var cookieScheme = _cookieService.GetCookieSchemeForClient(clientId);
        try { var cookieResult = await context.AuthenticateAsync(cookieScheme); if (cookieResult.Succeeded && cookieResult.Principal?.Identity?.IsAuthenticated == true) authPrincipal = cookieResult.Principal; }
        catch (Exception ex){ _logger.LogDebug(ex, "Cookie auth failed for scheme {Scheme}", cookieScheme); }
        if (authPrincipal == null)
        {
            var fallback = await context.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
            authPrincipal = fallback.Principal;
        }
        if (authPrincipal == null) return Results.Forbid(authenticationSchemes: new[] { OpenIddictServerAspNetCoreDefaults.AuthenticationScheme });

        var sub = authPrincipal.FindFirst(OpenIddictConstants.Claims.Subject)?.Value;
        if (string.IsNullOrWhiteSpace(sub)) return Results.Forbid(authenticationSchemes: new[] { OpenIddictServerAspNetCoreDefaults.AuthenticationScheme });
        var user = await _userManager.FindByIdAsync(sub);
        if (user == null) return Results.Forbid(authenticationSchemes: new[] { OpenIddictServerAspNetCoreDefaults.AuthenticationScheme });

        var scopes = request.GetScopes();
        // Build fresh identity (ensures updated roles/claims)
        var identity = await BuildUserIdentityAsync(user, clientId, scopes);
        // Preserve extra claims (e.g., amr) from original principal if not already present
        var existingTypes = identity.Claims.Select(c => c.Type).ToHashSet(StringComparer.OrdinalIgnoreCase);
        foreach (var c in authPrincipal.Claims)
        {
            if (existingTypes.Contains(c.Type)) continue; // skip duplicates
            if (c.Type is OpenIddictConstants.Claims.Subject or OpenIddictConstants.Claims.Email or OpenIddictConstants.Claims.Name or OpenIddictConstants.Claims.PreferredUsername) continue; // already set with destinations
            var clone = new Claim(c.Type, c.Value, c.ValueType, c.Issuer, c.OriginalIssuer);
            clone.SetDestinations(Destinations.AccessToken); // default to access token
            identity.AddClaim(clone);
        }

        var principal = new ClaimsPrincipal(identity);
        principal.SetScopes(scopes);
        var audienceResult = await ApplyAudiencesAsync(principal, clientId, scopes, context);
        if (audienceResult.Error)
        {
            var forbidProps = new AuthenticationProperties(new Dictionary<string, string?>
            {
                [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidScope,
                [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = audienceResult.Description ?? "Required audience scope not requested"
            });
            return Results.Forbid(forbidProps, new[] { OpenIddictServerAspNetCoreDefaults.AuthenticationScheme });
        }
        return Results.SignIn(principal, authenticationScheme: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }

    private async Task<IResult> HandleRefreshTokenGrantAsync(HttpContext context, OpenIddictRequest request)
    {
        var authenticateResult = await context.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        var principal = authenticateResult.Principal;
        if (principal == null) return Results.Forbid(authenticationSchemes: new[] { OpenIddictServerAspNetCoreDefaults.AuthenticationScheme });
        var sub = principal.FindFirst(OpenIddictConstants.Claims.Subject)?.Value;
        if (string.IsNullOrWhiteSpace(sub)) return Results.Forbid(authenticationSchemes: new[] { OpenIddictServerAspNetCoreDefaults.AuthenticationScheme });
        var user = await _userManager.FindByIdAsync(sub);
        if (user == null) return Results.Forbid(authenticationSchemes: new[] { OpenIddictServerAspNetCoreDefaults.AuthenticationScheme });
        if (!user.EmailConfirmed && _userManager.Options.SignIn.RequireConfirmedEmail) return Results.Forbid(authenticationSchemes: new[] { OpenIddictServerAspNetCoreDefaults.AuthenticationScheme });
        var scopes = request.GetScopes();
        var identity = await BuildUserIdentityAsync(user, request.ClientId!, scopes);
        var newPrincipal = new ClaimsPrincipal(identity);
        newPrincipal.SetScopes(scopes);
        var audienceResult = await ApplyAudiencesAsync(newPrincipal, request.ClientId!, scopes, context);
        if (audienceResult.Error)
        {
            var forbidProps = new AuthenticationProperties(new Dictionary<string, string?>
            {
                [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidScope,
                [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = audienceResult.Description ?? "Required audience scope not requested"
            });
            return Results.Forbid(forbidProps, new[] { OpenIddictServerAspNetCoreDefaults.AuthenticationScheme });
        }
        // Update session cookie if possible
        var cookieScheme = _cookieService.GetCookieSchemeForClient(request.ClientId!);
        try { await context.SignInAsync(cookieScheme, newPrincipal); } catch { }
        return Results.SignIn(newPrincipal, authenticationScheme: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
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
    private async Task AddProfileClaimsAsync(ClaimsIdentity identity, IdentityUser user, IEnumerable<string> scopes, Client? client)
    {
        try
        {
            // Load client to respect AlwaysIncludeUserClaimsInIdToken flag
            var includeInId = client?.AlwaysIncludeUserClaimsInIdToken == true; // default false if null

            var destinations = includeInId
                ? new[] { Destinations.AccessToken, Destinations.IdentityToken }
                : new[] { Destinations.AccessToken }; // userinfo-only exposure for privacy

            var claims = await _userManager.GetClaimsAsync(user);
            
            // Only include profile claims if profile scope is requested
            if (scopes.Contains(OpenIddictConstants.Scopes.Profile))
            {
                // Add given_name if available
                var givenName = claims.FirstOrDefault(c => c.Type == "given_name")?.Value;
                if (!string.IsNullOrEmpty(givenName))
                {
                    var givenNameClaim = new Claim(OpenIddictConstants.Claims.GivenName, givenName);
                    givenNameClaim.SetDestinations(destinations);
                    identity.AddClaim(givenNameClaim);
                }

                // Add family_name if available
                var familyName = claims.FirstOrDefault(c => c.Type == "family_name")?.Value;
                if (!string.IsNullOrEmpty(familyName))
                {
                    var familyNameClaim = new Claim(OpenIddictConstants.Claims.FamilyName, familyName);
                    familyNameClaim.SetDestinations(destinations);
                    identity.AddClaim(familyNameClaim);
                }

                // Add other profile claims as needed
                var picture = claims.FirstOrDefault(c => c.Type == "picture")?.Value;
                if (!string.IsNullOrEmpty(picture))
                {
                    var pictureClaim = new Claim(OpenIddictConstants.Claims.Picture, picture);
                    pictureClaim.SetDestinations(destinations);
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

    private sealed record AudienceApplyResult(bool Error, string? Description = null);

    private async Task<AudienceApplyResult> ApplyAudiencesAsync(ClaimsPrincipal principal, string clientId, IEnumerable<string> requestedScopes, HttpContext? httpContext)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(clientId)) return new(false);
            var scopeSet = requestedScopes?.ToHashSet(StringComparer.OrdinalIgnoreCase) ?? new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var client = await _db.Clients.Include(c => c.Audiences).Include(c=>c.Realm).FirstOrDefaultAsync(c => c.ClientId == clientId);
            if (client == null) return new(false);
            var mode = client.AudienceMode ?? client.Realm?.AudienceMode ?? AudienceMode.RequestedIntersection;
            var includeInId = client.IncludeAudInIdToken ?? client.Realm?.IncludeAudInIdToken ?? true;
            var explicitRequired = client.RequireExplicitAudienceScope ?? client.Realm?.RequireExplicitAudienceScope ?? false;
            var primary = client.PrimaryAudience ?? client.Realm?.PrimaryAudience;
            var configured = client.Audiences.Select(a => a.Audience).Where(a=>!string.IsNullOrWhiteSpace(a)).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
            if (configured.Count==0 || mode==AudienceMode.None) return new(false);
            var intersection = configured.Where(a => scopeSet.Contains(a)).ToList();

            List<string> result = new();
            switch (mode)
            {
                case AudienceMode.RequestedIntersection:
                    result = intersection; break;
                case AudienceMode.AllConfigured:
                    result = configured; break;
                case AudienceMode.RequestedOrAll:
                    result = intersection.Count>0 ? intersection : configured; break;
                case AudienceMode.RequestedOrPrimary:
                    if (intersection.Count>0) result = intersection;
                    else if (!string.IsNullOrWhiteSpace(primary) && configured.Contains(primary, StringComparer.OrdinalIgnoreCase)) result = new(){primary!};
                    else result = new(){configured.First()};
                    break;
                case AudienceMode.ErrorIfUnrequested:
                    if (intersection.Count==0)
                        return new(true, "Required audience scope missing");
                    result = intersection; break;
                case AudienceMode.AccessTokenOnly:
                    result = intersection; break;
            }

            if (explicitRequired && intersection.Count==0 && mode != AudienceMode.AllConfigured)
            {
                // explicit flag demands at least one requested audience
                return new(true, "Explicit audience scope required");
            }

            if (result.Count==0) return new(false);
            if (principal.HasClaim(c=>c.Type==Claims.Audience)) return new(false);

            foreach (var aud in result.Distinct())
            {
                var claim = new Claim(Claims.Audience, aud);
                if (mode == AudienceMode.AccessTokenOnly || !includeInId)
                {
                    claim.SetDestinations(Destinations.AccessToken);
                }
                else
                {
                    claim.SetDestinations(Destinations.AccessToken, Destinations.IdentityToken);
                }
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
}