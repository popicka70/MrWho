using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Authentication;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using System.Security.Claims;
using Microsoft.AspNetCore;
using MrWho.Services;

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
    private readonly ILogger<TokenHandler> _logger;

    public TokenHandler(
        UserManager<IdentityUser> userManager,
        SignInManager<IdentityUser> signInManager,
        IClientCookieConfigurationService cookieService,
        ILogger<TokenHandler> logger)
    {
        _userManager = userManager;
        _signInManager = signInManager;
        _cookieService = cookieService;
        _logger = logger;
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
            return HandleClientCredentialsGrant(request);
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

    private async Task<IResult> HandlePasswordGrantAsync(HttpContext context, OpenIddictRequest request)
    {
        var user = await _userManager.FindByNameAsync(request.Username!);

        if (user != null && await _userManager.CheckPasswordAsync(user, request.Password!))
        {
            // Get client-specific authentication scheme if available
            var clientId = request.ClientId!;
            var cookieScheme = _cookieService.GetCookieSchemeForClient(clientId);
            var scopes = request.GetScopes();

            var identity = new ClaimsIdentity(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
            
            var subClaim = new Claim(OpenIddictConstants.Claims.Subject, user.Id);
            subClaim.SetDestinations(OpenIddictConstants.Destinations.AccessToken, OpenIddictConstants.Destinations.IdentityToken);
            identity.AddClaim(subClaim);

            var emailClaim = new Claim(OpenIddictConstants.Claims.Email, user.Email!);
            emailClaim.SetDestinations(OpenIddictConstants.Destinations.AccessToken, OpenIddictConstants.Destinations.IdentityToken);
            identity.AddClaim(emailClaim);
            
            // Get the user's name claim, fallback to friendly name from username
            var userName = await GetUserNameClaimAsync(user);
            var nameClaim = new Claim(OpenIddictConstants.Claims.Name, userName);
            nameClaim.SetDestinations(OpenIddictConstants.Destinations.AccessToken, OpenIddictConstants.Destinations.IdentityToken);
            identity.AddClaim(nameClaim);

            var preferredUsernameClaim = new Claim(OpenIddictConstants.Claims.PreferredUsername, user.UserName!);
            preferredUsernameClaim.SetDestinations(OpenIddictConstants.Destinations.AccessToken, OpenIddictConstants.Destinations.IdentityToken);
            identity.AddClaim(preferredUsernameClaim);

            // Add other profile claims if available
            await AddProfileClaimsAsync(identity, user, scopes);

            // Add roles
            var roles = await _userManager.GetRolesAsync(user);
            foreach (var role in roles)
            {
                var roleClaim = new Claim(OpenIddictConstants.Claims.Role, role);
                roleClaim.SetDestinations(OpenIddictConstants.Destinations.AccessToken, OpenIddictConstants.Destinations.IdentityToken);
                identity.AddClaim(roleClaim);
            }

            var principal = new ClaimsPrincipal(identity);
            principal.SetScopes(request.GetScopes());

            // Sign in with client-specific cookie scheme for session management
            try
            {
                await context.SignInAsync(cookieScheme, principal);
                _logger.LogDebug("Signed in user {Username} with client-specific scheme {Scheme}", 
                    user.UserName, cookieScheme);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to sign in with client-specific scheme {Scheme}, using default", 
                    cookieScheme);
                // Fallback to default identity scheme
                await _signInManager.SignInAsync(user, isPersistent: false);
            }

            return Results.SignIn(principal, authenticationScheme: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        var properties = new AuthenticationProperties(new Dictionary<string, string?>
        {
            [OpenIddictServerAspNetCoreConstants.Properties.Error] = OpenIddictConstants.Errors.InvalidGrant,
            [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "The username/password couple is invalid."
        });

        return Results.Forbid(properties, new[] { OpenIddictServerAspNetCoreDefaults.AuthenticationScheme });
    }

    private static IResult HandleClientCredentialsGrant(OpenIddictRequest request)
    {
        var identity = new ClaimsIdentity(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        var subClaim = new Claim(OpenIddictConstants.Claims.Subject, request.ClientId!);
        subClaim.SetDestinations(OpenIddictConstants.Destinations.AccessToken);
        identity.AddClaim(subClaim);

        var principal = new ClaimsPrincipal(identity);
        principal.SetScopes(request.GetScopes());

        return Results.SignIn(principal, authenticationScheme: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }

    private async Task<IResult> HandleAuthorizationCodeGrantAsync(HttpContext context, OpenIddictRequest request)
    {
        // Try to authenticate with client-specific scheme first
        ClaimsPrincipal? principal = null;
        var clientId = request.ClientId!;
        var cookieScheme = _cookieService.GetCookieSchemeForClient(clientId);

        try
        {
            var clientAuthResult = await context.AuthenticateAsync(cookieScheme);
            if (clientAuthResult.Succeeded && clientAuthResult.Principal?.Identity?.IsAuthenticated == true)
            {
                principal = clientAuthResult.Principal;
                _logger.LogDebug("Authenticated authorization code with client-specific scheme {Scheme}", cookieScheme);
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Failed to authenticate with client-specific scheme {Scheme}", cookieScheme);
        }

        // Fallback to OpenIddict authentication
        if (principal == null)
        {
            var authenticateResult = await context.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
            principal = authenticateResult.Principal;
            _logger.LogDebug("Using OpenIddict authentication for authorization code");
        }
        
        if (principal == null)
        {
            _logger.LogWarning("Authorization code authentication failed: no principal found");
            return Results.Forbid(authenticationSchemes: new[] { OpenIddictServerAspNetCoreDefaults.AuthenticationScheme });
        }

        // Create a new identity for the access token with the claims from the authorization code
        var identity = new ClaimsIdentity(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        
        // Copy the claims from the principal stored in the authorization code, preserving destinations
        var subjectClaim = principal.FindFirst(OpenIddictConstants.Claims.Subject);
        var nameClaim = principal.FindFirst(OpenIddictConstants.Claims.Name);
        var emailClaim = principal.FindFirst(OpenIddictConstants.Claims.Email);
        var preferredUsernameClaim = principal.FindFirst(OpenIddictConstants.Claims.PreferredUsername);
        var givenNameClaim = principal.FindFirst(OpenIddictConstants.Claims.GivenName);
        var familyNameClaim = principal.FindFirst(OpenIddictConstants.Claims.FamilyName);
        
        if (subjectClaim != null)
        {
            var newSubClaim = new Claim(OpenIddictConstants.Claims.Subject, subjectClaim.Value);
            newSubClaim.SetDestinations(OpenIddictConstants.Destinations.AccessToken, OpenIddictConstants.Destinations.IdentityToken);
            identity.AddClaim(newSubClaim);
        }
        if (nameClaim != null)
        {
            var newNameClaim = new Claim(OpenIddictConstants.Claims.Name, nameClaim.Value);
            newNameClaim.SetDestinations(OpenIddictConstants.Destinations.AccessToken, OpenIddictConstants.Destinations.IdentityToken);
            identity.AddClaim(newNameClaim);
        }
        if (emailClaim != null)
        {
            var newEmailClaim = new Claim(OpenIddictConstants.Claims.Email, emailClaim.Value);
            newEmailClaim.SetDestinations(OpenIddictConstants.Destinations.AccessToken, OpenIddictConstants.Destinations.IdentityToken);
            identity.AddClaim(newEmailClaim);
        }
        if (preferredUsernameClaim != null)
        {
            var newPreferredUsernameClaim = new Claim(OpenIddictConstants.Claims.PreferredUsername, preferredUsernameClaim.Value);
            newPreferredUsernameClaim.SetDestinations(OpenIddictConstants.Destinations.AccessToken, OpenIddictConstants.Destinations.IdentityToken);
            identity.AddClaim(newPreferredUsernameClaim);
        }
        if (givenNameClaim != null)
        {
            var newGivenNameClaim = new Claim(OpenIddictConstants.Claims.GivenName, givenNameClaim.Value);
            newGivenNameClaim.SetDestinations(OpenIddictConstants.Destinations.AccessToken, OpenIddictConstants.Destinations.IdentityToken);
            identity.AddClaim(newGivenNameClaim);
        }
        if (familyNameClaim != null)
        {
            var newFamilyNameClaim = new Claim(OpenIddictConstants.Claims.FamilyName, familyNameClaim.Value);
            newFamilyNameClaim.SetDestinations(OpenIddictConstants.Destinations.AccessToken, OpenIddictConstants.Destinations.IdentityToken);
            identity.AddClaim(newFamilyNameClaim);
        }

        // Copy role claims
        var roleClaims = principal.FindAll(OpenIddictConstants.Claims.Role);
        foreach (var roleClaim in roleClaims)
        {
            var newRoleClaim = new Claim(OpenIddictConstants.Claims.Role, roleClaim.Value);
            newRoleClaim.SetDestinations(OpenIddictConstants.Destinations.AccessToken, OpenIddictConstants.Destinations.IdentityToken);
            identity.AddClaim(newRoleClaim);
        }
        
        var newPrincipal = new ClaimsPrincipal(identity);
        newPrincipal.SetScopes(request.GetScopes());

        return Results.SignIn(newPrincipal, authenticationScheme: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }

    private async Task<IResult> HandleRefreshTokenGrantAsync(HttpContext context, OpenIddictRequest request)
    {
        // Authenticate the refresh token and extract the principal
        var authenticateResult = await context.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        var principal = authenticateResult.Principal;
        
        if (principal == null)
        {
            _logger.LogWarning("Refresh token authentication failed: no principal found");
            return Results.Forbid(authenticationSchemes: new[] { OpenIddictServerAspNetCoreDefaults.AuthenticationScheme });
        }

        // Extract the user ID from the refresh token principal
        var subjectClaim = principal.FindFirst(OpenIddictConstants.Claims.Subject);
        if (subjectClaim == null)
        {
            _logger.LogWarning("Refresh token authentication failed: no subject claim found");
            return Results.Forbid(authenticationSchemes: new[] { OpenIddictServerAspNetCoreDefaults.AuthenticationScheme });
        }

        // Get the user from the database to ensure they still exist and are valid
        var user = await _userManager.FindByIdAsync(subjectClaim.Value);
        if (user == null)
        {
            _logger.LogWarning("Refresh token authentication failed: user not found for subject {Subject}", subjectClaim.Value);
            return Results.Forbid(authenticationSchemes: new[] { OpenIddictServerAspNetCoreDefaults.AuthenticationScheme });
        }

        // Check if the user is still enabled (you can add additional checks here if needed)
        if (!user.EmailConfirmed && _userManager.Options.SignIn.RequireConfirmedEmail)
        {
            _logger.LogWarning("Refresh token authentication failed: user {UserName} email not confirmed", user.UserName);
            return Results.Forbid(authenticationSchemes: new[] { OpenIddictServerAspNetCoreDefaults.AuthenticationScheme });
        }

        // Create a new identity with fresh user information
        var identity = new ClaimsIdentity(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        var scopes = request.GetScopes();
        
        var subClaim = new Claim(OpenIddictConstants.Claims.Subject, user.Id);
        subClaim.SetDestinations(OpenIddictConstants.Destinations.AccessToken, OpenIddictConstants.Destinations.IdentityToken);
        identity.AddClaim(subClaim);

        var emailClaim = new Claim(OpenIddictConstants.Claims.Email, user.Email!);
        emailClaim.SetDestinations(OpenIddictConstants.Destinations.AccessToken, OpenIddictConstants.Destinations.IdentityToken);
        identity.AddClaim(emailClaim);
        
        // Get the user's name claim, fallback to friendly name from username
        var userName = await GetUserNameClaimAsync(user);
        var nameClaim = new Claim(OpenIddictConstants.Claims.Name, userName);
        nameClaim.SetDestinations(OpenIddictConstants.Destinations.AccessToken, OpenIddictConstants.Destinations.IdentityToken);
        identity.AddClaim(nameClaim);

        var preferredUsernameClaim = new Claim(OpenIddictConstants.Claims.PreferredUsername, user.UserName!);
        preferredUsernameClaim.SetDestinations(OpenIddictConstants.Destinations.AccessToken, OpenIddictConstants.Destinations.IdentityToken);
        identity.AddClaim(preferredUsernameClaim);

        // Add other profile claims if available
        await AddProfileClaimsAsync(identity, user, scopes);

        // Add any additional claims you might need (roles, etc.)
        var roles = await _userManager.GetRolesAsync(user);
        foreach (var role in roles)
        {
            var roleClaim = new Claim(OpenIddictConstants.Claims.Role, role);
            roleClaim.SetDestinations(OpenIddictConstants.Destinations.AccessToken, OpenIddictConstants.Destinations.IdentityToken);
            identity.AddClaim(roleClaim);
        }

        var newPrincipal = new ClaimsPrincipal(identity);
        newPrincipal.SetScopes(request.GetScopes());

        // Update client-specific session if available
        var clientId = request.ClientId!;
        var cookieScheme = _cookieService.GetCookieSchemeForClient(clientId);
        try
        {
            await context.SignInAsync(cookieScheme, newPrincipal);
            _logger.LogDebug("Updated client-specific session for user {UserName} with scheme {Scheme}", 
                user.UserName, cookieScheme);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Failed to update client-specific session with scheme {Scheme}", cookieScheme);
        }

        _logger.LogDebug("Refresh token grant successful for user: {UserName}", user.UserName);
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
    private async Task AddProfileClaimsAsync(ClaimsIdentity identity, IdentityUser user, IEnumerable<string> scopes)
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
                    identity.AddClaim(givenNameClaim);
                }

                // Add family_name if available
                var familyName = claims.FirstOrDefault(c => c.Type == "family_name")?.Value;
                if (!string.IsNullOrEmpty(familyName))
                {
                    var familyNameClaim = new Claim(OpenIddictConstants.Claims.FamilyName, familyName);
                    familyNameClaim.SetDestinations(OpenIddictConstants.Destinations.AccessToken, OpenIddictConstants.Destinations.IdentityToken);
                    identity.AddClaim(familyNameClaim);
                }

                // Add other profile claims as needed
                var picture = claims.FirstOrDefault(c => c.Type == "picture")?.Value;
                if (!string.IsNullOrEmpty(picture))
                {
                    var pictureClaim = new Claim(OpenIddictConstants.Claims.Picture, picture);
                    pictureClaim.SetDestinations(OpenIddictConstants.Destinations.AccessToken, OpenIddictConstants.Destinations.IdentityToken);
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
}