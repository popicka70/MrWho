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

        // Check if user is authenticated for this specific client using the dynamic cookie service
        ClaimsPrincipal? principal = null;
        try
        {
            if (await _dynamicCookieService.IsAuthenticatedForClientAsync(clientId))
            {
                principal = await _dynamicCookieService.GetClientPrincipalAsync(clientId);
                if (principal?.Identity?.IsAuthenticated == true)
                {
                    _logger.LogDebug("User already authenticated for client {ClientId}", clientId);
                }
                else
                {
                    principal = null;
                    _logger.LogDebug("User cookie exists but principal is invalid for client {ClientId}", clientId);
                }
            }
            else
            {
                _logger.LogDebug("User not authenticated for client {ClientId}", clientId);
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Failed to check authentication for client {ClientId}", clientId);
        }

        // If user is not authenticated with THIS client, trigger login
        if (principal == null)
        {
            _logger.LogDebug("User not authenticated for client {ClientId}, triggering login challenge", 
                clientId);
            
            // Store the authorization request parameters for later use
            var properties = new AuthenticationProperties
            {
                RedirectUri = context.Request.GetDisplayUrl(),
                Items =
                {
                    ["client_id"] = clientId,
                    ["return_url"] = context.Request.GetDisplayUrl()
                }
            };

            // Store client ID in session for callback handling
            if (context.Session.IsAvailable)
            {
                context.Session.Set("oidc_client_id", System.Text.Encoding.UTF8.GetBytes(clientId));
            }

            // Redirect to login with client ID parameter
            var loginUrl = $"/connect/login?clientId={Uri.EscapeDataString(clientId)}&returnUrl={Uri.EscapeDataString(context.Request.GetDisplayUrl())}";
            return Results.Redirect(loginUrl);
        }

        // User is authenticated with the correct client scheme, create authorization code
        var identity = new ClaimsIdentity(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);

        // Get user from database to ensure we have the latest information
        var subjectClaim = principal.FindFirst(ClaimTypes.NameIdentifier) ?? 
                          principal.FindFirst(OpenIddictConstants.Claims.Subject);
        
        if (subjectClaim == null)
        {
            _logger.LogWarning("? No subject claim found in authenticated principal for client {ClientId}", clientId);
            _logger.LogWarning("   ?? Available claims: {Claims}", 
                string.Join(", ", principal.Claims.Select(c => $"{c.Type}={c.Value}")));
            _logger.LogWarning("   ?? Looking for: {NameId} OR {Subject}", 
                ClaimTypes.NameIdentifier, OpenIddictConstants.Claims.Subject);
            return Results.Forbid();
        }

        _logger.LogDebug("? Subject claim found: Type='{ClaimType}', Value='{ClaimValue}'", 
            subjectClaim.Type, subjectClaim.Value);

        var user = await _userManager.FindByIdAsync(subjectClaim.Value);
        if (user == null)
        {
            _logger.LogWarning("? User not found for subject {Subject} (client: {ClientId})", subjectClaim.Value, clientId);
            _logger.LogWarning("   ?? Subject claim type: {ClaimType}", subjectClaim.Type);
            return Results.Forbid();
        }

        _logger.LogDebug("? User found: {UserName} (ID: {UserId}) for client {ClientId}", 
            user.UserName, user.Id, clientId);

        // New: enforce user profile state must be Active
        try
        {
            var profile = await _context.UserProfiles.AsNoTracking().FirstOrDefaultAsync(p => p.UserId == user.Id);
            if (profile == null)
            {
                _logger.LogWarning("User {UserName} has no profile. Denying authorization.", user.UserName);
                await SafeSignOutClientAsync(clientId);
                return Results.Forbid();
            }

            if (profile.State != UserState.Active)
            {
                _logger.LogWarning("User {UserName} state is {State}. Denying authorization for client {ClientId}.", user.UserName, profile.State, clientId);
                await SafeSignOutClientAsync(clientId);
                return Results.Forbid();
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error checking user profile state for user {UserId}", user.Id);
            await SafeSignOutClientAsync(clientId);
            return Results.Forbid();
        }

        // CRITICAL: Validate user can access this client based on realm restrictions
        var realmValidation = await _realmValidationService.ValidateUserRealmAccessAsync(user, clientId);
        if (!realmValidation.IsValid)
        {
            _logger.LogWarning("?? REALM VALIDATION FAILED: User {UserName} denied access to client {ClientId}: {Reason} (ErrorCode: {ErrorCode})", 
                user.UserName, clientId, realmValidation.Reason, realmValidation.ErrorCode);
            _logger.LogWarning("   ?? Realm Details: UserRealm='{UserRealm}', ClientRealm='{ClientRealm}'", 
                realmValidation.UserRealm, realmValidation.ClientRealm);

            await SafeSignOutClientAsync(clientId);

            // Return access denied error
            return Results.Forbid();
        }

        _logger.LogInformation("? REALM VALIDATION PASSED: User {UserName} authorized for client {ClientId} (UserRealm: '{UserRealm}', ClientRealm: '{ClientRealm}')", 
            user.UserName, clientId, realmValidation.UserRealm, realmValidation.ClientRealm);

        // User is authenticated and authorized for this client, create authorization code
        var claimsIdentity = new ClaimsIdentity(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);

        // Get requested scopes to determine claim destinations
        var scopes = request.GetScopes();

        // Create claims for the authorization code with proper destinations
        var subClaim = new Claim(OpenIddictConstants.Claims.Subject, user.Id);
        subClaim.SetDestinations(OpenIddictConstants.Destinations.AccessToken, OpenIddictConstants.Destinations.IdentityToken);
        claimsIdentity.AddClaim(subClaim);

        var emailClaim = new Claim(OpenIddictConstants.Claims.Email, user.Email!);
        emailClaim.SetDestinations(OpenIddictConstants.Destinations.AccessToken, OpenIddictConstants.Destinations.IdentityToken);
        claimsIdentity.AddClaim(emailClaim);
        
        // Get the user's name claim, fallback to friendly name from username
        var userName = await GetUserNameClaimAsync(user);
        var nameClaim = new Claim(OpenIddictConstants.Claims.Name, userName);
        nameClaim.SetDestinations(OpenIddictConstants.Destinations.AccessToken, OpenIddictConstants.Destinations.IdentityToken);
        claimsIdentity.AddClaim(nameClaim);

        var preferredUsernameClaim = new Claim(OpenIddictConstants.Claims.PreferredUsername, user.UserName!);
        preferredUsernameClaim.SetDestinations(OpenIddictConstants.Destinations.AccessToken, OpenIddictConstants.Destinations.IdentityToken);
        claimsIdentity.AddClaim(preferredUsernameClaim);

        // Add other profile claims with proper destinations if available
        await AddProfileClaimsAsync(claimsIdentity, user, scopes);

        // Add roles with proper destinations
        var roles = await _userManager.GetRolesAsync(user);
        foreach (var role in roles)
        {
            var roleClaim = new Claim(OpenIddictConstants.Claims.Role, role);
            roleClaim.SetDestinations(OpenIddictConstants.Destinations.AccessToken, OpenIddictConstants.Destinations.IdentityToken);
            claimsIdentity.AddClaim(roleClaim);
        }

        // Propagate AMR (Authentication Methods References) claims if present so clients know MFA was used
        try
        {
            var amrClaims = principal?.FindAll("amr")?.ToList();
            if (amrClaims != null && amrClaims.Count > 0)
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
            _logger.LogDebug(ex, "Failed to propagate amr claims to authorization identity");
        }

        var authPrincipal = new ClaimsPrincipal(claimsIdentity);
        authPrincipal.SetScopes(request.GetScopes());

        // Sign in the user with the client-specific scheme if not already done
        // CRITICAL: Ensure user is signed in with the client-specific scheme for proper session isolation
        if (!await _dynamicCookieService.IsAuthenticatedForClientAsync(clientId))
        {
            _logger.LogDebug("User not signed in with client-specific authentication, signing them in for client {ClientId}", clientId);
            try
            {
                await _dynamicCookieService.SignInWithClientCookieAsync(clientId, user, false);
                _logger.LogDebug("Successfully signed in user {UserName} with client-specific authentication", 
                    user.UserName);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to sign in with client-specific authentication");
            }
        }

        _logger.LogDebug("Authorization granted for user {UserName} and client {ClientId}", 
            user.UserName, clientId);

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
    private async Task AddProfileClaimsAsync(ClaimsIdentity claimsIdentity, IdentityUser user, IEnumerable<string> scopes)
    {
        try
        {
            var claims = await _userManager.GetClaimsAsync(user);
            
            // Only include profile claims if profile scope is requested
            if (scopes.Contains(OpenIddictConstants.Scopes.Profile))
            {
                // Add given_name if available
                var givenName = claims.FirstOrDefault(c => c.Type == "given_name")?.Value;
                if (!string.IsNullOrEmpty(givenName))
                {
                    var givenNameClaim = new Claim(OpenIddictConstants.Claims.GivenName, givenName);
                    givenNameClaim.SetDestinations(OpenIddictConstants.Destinations.AccessToken, OpenIddictConstants.Destinations.IdentityToken);
                    claimsIdentity.AddClaim(givenNameClaim);
                }

                // Add family_name if available
                var familyName = claims.FirstOrDefault(c => c.Type == "family_name")?.Value;
                if (!string.IsNullOrEmpty(familyName))
                {
                    var familyNameClaim = new Claim(OpenIddictConstants.Claims.FamilyName, familyName);
                    familyNameClaim.SetDestinations(OpenIddictConstants.Destinations.AccessToken, OpenIddictConstants.Destinations.IdentityToken);
                    claimsIdentity.AddClaim(familyNameClaim);
                }

                // Add other profile claims as needed
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
}