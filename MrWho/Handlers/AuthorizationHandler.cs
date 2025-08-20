using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Authentication;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using System.Security.Claims;
using MrWho.Services;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.AspNetCore;
using MrWho.Data;
using Microsoft.EntityFrameworkCore;
using MrWho.Models;

namespace MrWho.Handlers;

public interface IOidcAuthorizationHandler
{
    Task<IResult> HandleAuthorizationRequestAsync(HttpContext context);
}

public class OidcAuthorizationHandler : IOidcAuthorizationHandler
{
    private readonly UserManager<IdentityUser> _userManager;
    private readonly SignInManager<IdentityUser> _signInManager;
    private readonly IClientCookieConfigurationService _cookieService;
    private readonly IDynamicCookieService _dynamicCookieService;
    private readonly IUserRealmValidationService _realmValidationService;
    private readonly ApplicationDbContext _context;
    private readonly ILogger<OidcAuthorizationHandler> _logger;

    public OidcAuthorizationHandler(
        UserManager<IdentityUser> userManager,
        SignInManager<IdentityUser> signInManager,
        IClientCookieConfigurationService cookieService,
        IDynamicCookieService dynamicCookieService,
        IUserRealmValidationService realmValidationService,
        ApplicationDbContext context,
        ILogger<OidcAuthorizationHandler> logger)
    {
        _userManager = userManager;
        _signInManager = signInManager;
        _cookieService = cookieService;
        _dynamicCookieService = dynamicCookieService;
        _realmValidationService = realmValidationService;
        _context = context;
        _logger = logger;
    }

    public async Task<IResult> HandleAuthorizationRequestAsync(HttpContext context)
    {
        var request = context.GetOpenIddictServerRequest() ??
                      throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

        var clientId = request.ClientId!;
        _logger.LogDebug("Authorization request received for client {ClientId}", clientId);

        ClaimsPrincipal? clientPrincipal = null;
        IdentityUser? authUser = null; // The user we will authorize
        ClaimsPrincipal? amrSource = null; // For AMR propagation

        // 1) Try client-specific cookie first
        try
        {
            if (await _dynamicCookieService.IsAuthenticatedForClientAsync(clientId))
            {
                clientPrincipal = await _dynamicCookieService.GetClientPrincipalAsync(clientId);
                if (clientPrincipal?.Identity?.IsAuthenticated == true)
                {
                    _logger.LogDebug("User already authenticated for client {ClientId}", clientId);
                    var sub = clientPrincipal.FindFirst(ClaimTypes.NameIdentifier) ??
                              clientPrincipal.FindFirst(OpenIddictConstants.Claims.Subject);
                    if (sub != null)
                    {
                        authUser = await _userManager.FindByIdAsync(sub.Value);
                        amrSource = clientPrincipal;
                    }
                }
                else
                {
                    clientPrincipal = null;
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Failed to check client cookie for {ClientId}", clientId);
        }

        // POP i'm not sure we need this, but keeping it for now
        // 2) Fallback to default Identity cookie and (conditionally) bootstrap client cookie
        if (authUser == null)
        {
            try
            {
                var defaultAuth = await context.AuthenticateAsync(IdentityConstants.ApplicationScheme);
                if (defaultAuth.Succeeded && defaultAuth.Principal?.Identity?.IsAuthenticated == true)
                {
                    var subj = defaultAuth.Principal.FindFirst(ClaimTypes.NameIdentifier) ??
                               defaultAuth.Principal.FindFirst(OpenIddictConstants.Claims.Subject) ??
                               defaultAuth.Principal.FindFirst("sub");
                    if (subj != null)
                    {
                        var candidateUser = await _userManager.FindByIdAsync(subj.Value);
                        if (candidateUser != null)
                        {
                            // IMPORTANT: only reuse the default cookie if this user is actually allowed for this client
                            try
                            {
                                var realmValidation = await _realmValidationService.ValidateUserRealmAccessAsync(candidateUser, clientId);
                                if (realmValidation.IsValid)
                                {
                                    authUser = candidateUser;
                                    amrSource = defaultAuth.Principal;
                                    _logger.LogDebug("Default Identity cookie authenticated. Using user {UserId} for client {ClientId}", subj.Value, clientId);
                                }
                                else
                                {
                                    _logger.LogInformation("Default Identity cookie user {UserId} is not valid for client {ClientId}: {Reason}. Forcing login for this client.", subj.Value, clientId, realmValidation.Reason);
                                }
                            }
                            catch (Exception ex)
                            {
                                _logger.LogWarning(ex, "Realm validation failed when checking default cookie user for {ClientId}", clientId);
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Default cookie fallback failed for {ClientId}", clientId);
            }
        }

        // 3) If we still don't have a user, issue an authentication challenge to the client-specific cookie scheme
        if (authUser == null)
        {
            _logger.LogDebug("No authenticated user found for client {ClientId}, issuing challenge to login", clientId);
            var cookieScheme = _cookieService.GetCookieSchemeForClient(clientId);
            var props = new AuthenticationProperties
            {
                RedirectUri = context.Request.GetDisplayUrl()
            };
            // Challenge will redirect to options.LoginPath (configured to /connect/login) and mark the request as handled
            return Results.Challenge(props, new[] { cookieScheme });
        }

        // 4) Realm and profile checks (defense-in-depth)
        try
        {
            var realmValidation = await _realmValidationService.ValidateUserRealmAccessAsync(authUser, clientId);
            if (!realmValidation.IsValid)
            {
                _logger.LogWarning("Access denied for user {UserName} to client {ClientId}. Reason: {Reason}", authUser.UserName, clientId, realmValidation.Reason);
                await SafeSignOutClientAsync(clientId);
                var forbidProps = new AuthenticationProperties(new Dictionary<string, string?>
                {
                    [OpenIddictServerAspNetCoreConstants.Properties.Error] = OpenIddictConstants.Errors.AccessDenied,
                    [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = realmValidation.Reason
                });
                return Results.Forbid(forbidProps, new[] { OpenIddictServerAspNetCoreDefaults.AuthenticationScheme });
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during realm validation for user {UserId} and client {ClientId}", authUser.Id, clientId);
            await SafeSignOutClientAsync(clientId);
            var forbidProps = new AuthenticationProperties(new Dictionary<string, string?>
            {
                [OpenIddictServerAspNetCoreConstants.Properties.Error] = OpenIddictConstants.Errors.ServerError,
                [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "Realm validation error"
            });
            return Results.Forbid(forbidProps, new[] { OpenIddictServerAspNetCoreDefaults.AuthenticationScheme });
        }

        try
        {
            var profile = await _context.UserProfiles.AsNoTracking().FirstOrDefaultAsync(p => p.UserId == authUser.Id);
            if (profile == null || profile.State != UserState.Active)
            {
                _logger.LogWarning("User {UserName} has invalid/missing profile for client {ClientId}", authUser.UserName, clientId);
                await SafeSignOutClientAsync(clientId);
                var forbidProps = new AuthenticationProperties(new Dictionary<string, string?>
                {
                    [OpenIddictServerAspNetCoreConstants.Properties.Error] = OpenIddictConstants.Errors.AccessDenied,
                    [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "Inactive user profile"
                });
                return Results.Forbid(forbidProps, new[] { OpenIddictServerAspNetCoreDefaults.AuthenticationScheme });
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error checking user profile state for user {UserId}", authUser.Id);
            await SafeSignOutClientAsync(clientId);
            var forbidProps = new AuthenticationProperties(new Dictionary<string, string?>
            {
                [OpenIddictServerAspNetCoreConstants.Properties.Error] = OpenIddictConstants.Errors.ServerError,
                [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "Profile validation error"
            });
            return Results.Forbid(forbidProps, new[] { OpenIddictServerAspNetCoreDefaults.AuthenticationScheme });
        }

        // 5) Build authorization principal
        var claimsIdentity = new ClaimsIdentity(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);

        var subClaim = new Claim(OpenIddictConstants.Claims.Subject, authUser.Id);
        subClaim.SetDestinations(OpenIddictConstants.Destinations.AccessToken, OpenIddictConstants.Destinations.IdentityToken);
        claimsIdentity.AddClaim(subClaim);

        var emailClaim = new Claim(OpenIddictConstants.Claims.Email, authUser.Email ?? string.Empty);
        emailClaim.SetDestinations(OpenIddictConstants.Destinations.AccessToken, OpenIddictConstants.Destinations.IdentityToken);
        claimsIdentity.AddClaim(emailClaim);

        var userName = await GetUserNameClaimAsync(authUser);
        var nameClaim = new Claim(OpenIddictConstants.Claims.Name, userName);
        nameClaim.SetDestinations(OpenIddictConstants.Destinations.AccessToken, OpenIddictConstants.Destinations.IdentityToken);
        claimsIdentity.AddClaim(nameClaim);

        var preferredUsernameClaim = new Claim(OpenIddictConstants.Claims.PreferredUsername, authUser.UserName ?? string.Empty);
        preferredUsernameClaim.SetDestinations(OpenIddictConstants.Destinations.AccessToken, OpenIddictConstants.Destinations.IdentityToken);
        claimsIdentity.AddClaim(preferredUsernameClaim);

        // Add extra profile claims and roles
        await AddProfileClaimsAsync(claimsIdentity, authUser, request.GetScopes());
        var roles = await _userManager.GetRolesAsync(authUser);
        foreach (var role in roles)
        {
            var roleClaim = new Claim(OpenIddictConstants.Claims.Role, role);
            roleClaim.SetDestinations(OpenIddictConstants.Destinations.AccessToken, OpenIddictConstants.Destinations.IdentityToken);
            claimsIdentity.AddClaim(roleClaim);
        }

        // Propagate AMR from whichever principal we have (client or default)
        try
        {
            var amrClaims = amrSource?.FindAll("amr")?.ToList();
            if (amrClaims != null)
            {
                foreach (var amr in amrClaims)
                {
                    var amrClaim = new Claim("amr", amr.Value);
                    amrClaim.SetDestinations(OpenIddictConstants.Destinations.AccessToken, OpenIddictConstants.Destinations.IdentityToken);
                    claimsIdentity.AddClaim(amrClaim);
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Failed to propagate amr claims");
        }

        var authPrincipal = new ClaimsPrincipal(claimsIdentity);
        authPrincipal.SetScopes(request.GetScopes());

        // Best-effort: ensure client cookie exists for next requests (only after validation)
        if (!await _dynamicCookieService.IsAuthenticatedForClientAsync(clientId))
        {
            try { await _dynamicCookieService.SignInWithClientCookieAsync(clientId, authUser, false); }
            catch (Exception ex) { _logger.LogDebug(ex, "Best-effort client cookie sign-in failed for {ClientId}", clientId); }
        }

        _logger.LogDebug("Authorization granted for user {UserName} and client {ClientId}", authUser.UserName, clientId);
        return Results.SignIn(authPrincipal, authenticationScheme: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }

    private async Task SafeSignOutClientAsync(string clientId)
    {
        try
        {
            await _dynamicCookieService.SignOutFromClientAsync(clientId);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to sign out from client-specific authentication");
        }
    }

    private async Task<string> GetUserNameClaimAsync(IdentityUser user)
    {
        try
        {
            var claims = await _userManager.GetClaimsAsync(user);
            var nameClaim = claims.FirstOrDefault(c => c.Type == "name")?.Value;
            if (!string.IsNullOrEmpty(nameClaim)) return nameClaim;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error retrieving name claim for user {UserId}", user.Id);
        }
        return ConvertToFriendlyName(user.UserName ?? "Unknown User");
    }

    private async Task AddProfileClaimsAsync(ClaimsIdentity claimsIdentity, IdentityUser user, IEnumerable<string> scopes)
    {
        try
        {
            var claims = await _userManager.GetClaimsAsync(user);
            if (scopes.Contains(OpenIddictConstants.Scopes.Profile))
            {
                var givenName = claims.FirstOrDefault(c => c.Type == "given_name")?.Value;
                if (!string.IsNullOrEmpty(givenName))
                {
                    var givenNameClaim = new Claim(OpenIddictConstants.Claims.GivenName, givenName);
                    givenNameClaim.SetDestinations(OpenIddictConstants.Destinations.AccessToken, OpenIddictConstants.Destinations.IdentityToken);
                    claimsIdentity.AddClaim(givenNameClaim);
                }
                var familyName = claims.FirstOrDefault(c => c.Type == "family_name")?.Value;
                if (!string.IsNullOrEmpty(familyName))
                {
                    var familyNameClaim = new Claim(OpenIddictConstants.Claims.FamilyName, familyName);
                    familyNameClaim.SetDestinations(OpenIddictConstants.Destinations.AccessToken, OpenIddictConstants.Destinations.IdentityToken);
                    claimsIdentity.AddClaim(familyNameClaim);
                }
                var picture = claims.FirstOrDefault(c => c.Type == "picture")?.Value;
                if (!string.IsNullOrEmpty(picture))
                {
                    var pictureClaim = new Claim(OpenIddictConstants.Claims.Picture, picture);
                    pictureClaim.SetDestinations(OpenIddictConstants.Destinations.AccessToken, OpenIddictConstants.Destinations.IdentityToken);
                    claimsIdentity.AddClaim(pictureClaim);
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error retrieving profile claims for user {UserId}", user.Id);
        }
    }

    private string ConvertToFriendlyName(string input)
    {
        if (string.IsNullOrEmpty(input))
            return "Unknown User";
        if (input.Contains('@'))
        {
            var localPart = input.Split('@')[0];
            return ConvertToDisplayName(localPart);
        }
        return ConvertToDisplayName(input);
    }

    private string ConvertToDisplayName(string input)
    {
        if (string.IsNullOrEmpty(input))
            return "Unknown User";
        var friendlyName = input.Replace('.', ' ').Replace('_', ' ').Replace('-', ' ');
        var words = friendlyName.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        var capitalizedWords = words.Select(word => word.Length > 0 ? char.ToUpper(word[0]) + word.Substring(1).ToLower() : word);
        return string.Join(" ", capitalizedWords);
    }
}