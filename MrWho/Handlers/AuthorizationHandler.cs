using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Authentication;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using System.Security.Claims;
using MrWho.Services; // includes IJarReplayCache, JarOptions
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.AspNetCore;
using MrWho.Data;
using Microsoft.EntityFrameworkCore;
using MrWho.Models;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.AspNetCore.DataProtection;
using System.Security.Cryptography;
using MrWho.Shared; // Jar/Jarm enums
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens; // modern validation

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
    private readonly IConsentService _consentService;
    private readonly ITimeLimitedDataProtector _mfaProtector;
    private readonly IKeyManagementService _keyService; // for RS256 validation
    private readonly IJarReplayCache _jarReplayCache;
    private readonly IOptions<JarOptions> _jarOptions;
    private readonly ISecurityAuditWriter _audit;
    private readonly IClientSecretService _clientSecretService; // new
    private const string MfaCookiePrefix = ".MrWho.Mfa.";

    private static readonly string[] MfaAmrValues = new[] { "mfa", "fido2" };

    private string? _mfaSatisfiedMethod; // track method when satisfied via grace cookie

    public OidcAuthorizationHandler(
        UserManager<IdentityUser> userManager,
        SignInManager<IdentityUser> signInManager,
        IClientCookieConfigurationService cookieService,
        IDynamicCookieService dynamicCookieService,
        IUserRealmValidationService realmValidationService,
        ApplicationDbContext context,
        ILogger<OidcAuthorizationHandler> logger,
        IConsentService consentService,
        IDataProtectionProvider dataProtectionProvider,
        IKeyManagementService keyService,
        IJarReplayCache jarReplayCache,
        IOptions<JarOptions> jarOptions,
        ISecurityAuditWriter audit,
        IClientSecretService clientSecretService) // inject
    {
        _userManager = userManager;
        _signInManager = signInManager;
        _cookieService = cookieService;
        _dynamicCookieService = dynamicCookieService;
        _realmValidationService = realmValidationService;
        _context = context;
        _logger = logger;
        _consentService = consentService;
        _mfaProtector = dataProtectionProvider.CreateProtector("MrWho.MfaCookie").ToTimeLimitedDataProtector();
        _keyService = keyService;
        _jarReplayCache = jarReplayCache;
        _jarOptions = jarOptions;
        _audit = audit;
        _clientSecretService = clientSecretService; // assign
    }

    public async Task<IResult> HandleAuthorizationRequestAsync(HttpContext context)
    {
        var request = context.GetOpenIddictServerRequest() ??
                      throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

        var clientId = request.ClientId ?? string.Empty;
        _logger.LogDebug("Authorization request received for client {ClientId}", clientId);

        // Ensure nonce from raw query (in case JAR omitted it but client handler still sent it separately)
        if (string.IsNullOrWhiteSpace(request.Nonce) && context.Request.Query.TryGetValue("nonce", out var rawNonce) && !string.IsNullOrWhiteSpace(rawNonce))
        {
            request.Nonce = rawNonce.ToString();
            _logger.LogDebug("Applied nonce from query string: {Nonce}", request.Nonce);
        }

        // JAR processing
        if (!string.IsNullOrEmpty(clientId))
        {
            try
            {
                var dbClient = await _context.Clients.AsNoTracking().FirstOrDefaultAsync(c => c.ClientId == clientId);
                if (dbClient != null)
                {
                    var jarMode = dbClient.JarMode ?? JarMode.Disabled;
                    var requestJwt = request.Request; // "request" parameter

                    if (jarMode == JarMode.Required && string.IsNullOrEmpty(requestJwt))
                    {
                        _logger.LogInformation("Client {ClientId} requires JAR but none supplied", clientId);
                        return Results.BadRequest(new
                        {
                            error = OpenIddictConstants.Errors.InvalidRequest,
                            error_description = "request object required"
                        });
                    }

                    if (!string.IsNullOrEmpty(requestJwt))
                    {
                        // Size limit check
                        var maxBytes = _jarOptions.Value.MaxRequestObjectBytes;
                        if (maxBytes > 0 && Encoding.UTF8.GetByteCount(requestJwt) > maxBytes)
                        {
                            return Results.BadRequest(new { error = OpenIddictConstants.Errors.InvalidRequestObject, error_description = "request object too large" });
                        }
                        var jarResult = await ValidateAndApplyJarAsync(dbClient, requestJwt, request, context);
                        if (jarResult is { } errorObject)
                        {
                            return Results.BadRequest(errorObject);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Unexpected error validating JAR for client {ClientId}", clientId);
                return Results.BadRequest(new { error = OpenIddictConstants.Errors.InvalidRequestObject, error_description = "invalid request object" });
            }
        }

        // Early scope validation
        try
        {
            var requestedScopes = request.GetScopes().ToList();
            if (!string.IsNullOrWhiteSpace(clientId) && requestedScopes.Count > 0)
            {
                var dbClient = await _context.Clients
                    .AsNoTracking()
                    .Include(c => c.Scopes)
                    .FirstOrDefaultAsync(c => c.ClientId == clientId);
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
            _logger.LogError(ex, "Failed during early scope validation for client {ClientId}", clientId);
        }

        ClaimsPrincipal? clientPrincipal = null;
        IdentityUser? authUser = null;
        ClaimsPrincipal? amrSource = null;

        // 1) Try client-specific cookie first
        try
        {
            if (await _dynamicCookieService.IsAuthenticatedForClientAsync(clientId))
            {
                clientPrincipal = await _dynamicCookieService.GetClientPrincipalAsync(clientId);
                if (clientPrincipal?.Identity?.IsAuthenticated == true)
                {
                    _logger.LogDebug("User already authenticated for client {ClientId}", clientId);
                    var sub = clientPrincipal.FindFirst(ClaimTypes.NameIdentifier) ?? clientPrincipal.FindFirst(OpenIddictConstants.Claims.Subject);
                    if (sub != null)
                    {
                        authUser = await _userManager.FindByIdAsync(sub.Value);
                        amrSource = clientPrincipal;
                    }
                }
                else clientPrincipal = null;
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Failed to check client cookie for {ClientId}", clientId);
        }

        // 2) Fallback to default Identity cookie
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
                                    _logger.LogInformation("Default Identity cookie user {UserId} not valid for client {ClientId}: {Reason}", subj.Value, clientId, realmValidation.Reason);
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

        // 3) Redirect to login if no user
        if (authUser == null)
        {
            _logger.LogDebug("No authenticated user found for client {ClientId}; redirecting to login", clientId);
            var originalAuthorizeUrl = context.Request.GetDisplayUrl();
            var loginUrl = "/connect/login?" +
                           $"returnUrl={Uri.EscapeDataString(originalAuthorizeUrl)}" +
                           (string.IsNullOrEmpty(clientId) ? string.Empty : $"&clientId={Uri.EscapeDataString(clientId)}");
            return Results.Redirect(loginUrl);
        }

        // Realm and profile checks
        try
        {
            var realmValidation = await _realmValidationService.ValidateUserRealmAccessAsync(authUser, clientId);
            if (!realmValidation.IsValid)
            {
                _logger.LogWarning("Access denied for user {UserName} to client {ClientId}. Reason: {Reason}", authUser.UserName, clientId, realmValidation.Reason);
                await SafeSignOutClientAsync(clientId);
                var accessDeniedUrl = BuildAccessDeniedUrl(context, clientId);
                return Results.Redirect(accessDeniedUrl);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Realm validation error for user {UserId} client {ClientId}", authUser.Id, clientId);
            await SafeSignOutClientAsync(clientId);
            var accessDeniedUrl = BuildAccessDeniedUrl(context, clientId);
            return Results.Redirect(accessDeniedUrl);
        }

        try
        {
            var profile = await _context.UserProfiles.AsNoTracking().FirstOrDefaultAsync(p => p.UserId == authUser.Id);
            if (profile == null || profile.State != UserState.Active)
            {
                _logger.LogWarning("User {UserName} has invalid/missing profile for client {ClientId}", authUser.UserName, clientId);
                await SafeSignOutClientAsync(clientId);
                var accessDeniedUrl = BuildAccessDeniedUrl(context, clientId);
                return Results.Redirect(accessDeniedUrl);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Profile state check failed for user {UserId}", authUser.Id);
            await SafeSignOutClientAsync(clientId);
            var accessDeniedUrl = BuildAccessDeniedUrl(context, clientId);
            return Results.Redirect(accessDeniedUrl);
        }

        // Consent
        try
        {
            try
            {
                var currentUrl = context.Request.GetDisplayUrl();
                var uri = new Uri(currentUrl);
                var q = QueryHelpers.ParseQuery(uri.Query);
                if (q.TryGetValue("mrwho_consent", out var v) && v.ToString() == "ok")
                {
                    goto SKIP_CONSENT;
                }
            }
            catch { }

            var requestedScopes = request.GetScopes();
            if (requestedScopes.Any())
            {
                var consent = await _consentService.GetAsync(authUser.Id, clientId);
                var granted = consent?.GetGrantedScopes() ?? Array.Empty<string>();
                var missing = _consentService.DiffMissingScopes(requestedScopes, granted);
                if (missing.Count > 0)
                {
                    var currentUrl = context.Request.GetDisplayUrl();
                    var scopesParam = string.Join(" ", requestedScopes);
                    var consentUrl = "/connect/consent?" +
                                     $"clientId={Uri.EscapeDataString(clientId)}&returnUrl={Uri.EscapeDataString(currentUrl)}" +
                                     (string.IsNullOrEmpty(scopesParam) ? string.Empty : $"&requested={Uri.EscapeDataString(scopesParam)}");
                    return Results.Redirect(consentUrl);
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Consent check failed for client {ClientId}; continuing", clientId);
        }

        SKIP_CONSENT:
        // MFA enforcement
        try
        {
            var dbClient = await _context.Clients.Include(c => c.Realm).FirstOrDefaultAsync(c => c.ClientId == clientId);
            if (dbClient != null)
            {
                var requireMfa = (dbClient.RequireMfa ?? dbClient.Realm?.DefaultRequireMfa ?? false);
                if (requireMfa)
                {
                    var allowedMethodsJson = dbClient.AllowedMfaMethods ?? dbClient.Realm?.DefaultAllowedMfaMethods;
                    var allowedList = new List<string>();
                    if (!string.IsNullOrWhiteSpace(allowedMethodsJson))
                    {
                        try { allowedList = System.Text.Json.JsonSerializer.Deserialize<List<string>>(allowedMethodsJson!) ?? new(); } catch { allowedList = new(); }
                    }
                    if (allowedList.Count == 0) allowedList = new List<string> { "totp", "fido2", "passkey" };

                    var currentAmr = amrSource?.FindAll("amr").Select(c => c.Value).ToList() ?? new List<string>();
                    var amrOk = currentAmr.Any(v => v == "mfa" || v == "fido2");

                    if (!amrOk)
                    {
                        var cookieName = MfaCookiePrefix + clientId;
                        if (context.Request.Cookies.TryGetValue(cookieName, out var raw))
                        {
                            try
                            {
                                var payload = _mfaProtector.Unprotect(raw, out var expiration);
                                var parts = payload.Split('|');
                                if (parts.Length >= 3 && parts[0] == "v1")
                                {
                                    var method = parts[1];
                                    bool isPasskey = method.Equals("fido2", StringComparison.OrdinalIgnoreCase) || method.Equals("passkey", StringComparison.OrdinalIgnoreCase);
                                    bool isTotp = method.Equals("totp", StringComparison.OrdinalIgnoreCase) || method.Equals("mfa", StringComparison.OrdinalIgnoreCase);
                                    var methodMatches = allowedList.Any(m => m.Equals(method, StringComparison.OrdinalIgnoreCase) || (m == "passkey" && isPasskey) || (m == "totp" && isTotp));
                                    if (methodMatches)
                                    {
                                        amrOk = true;
                                        _mfaSatisfiedMethod = isPasskey ? "fido2" : "mfa";
                                        _logger.LogDebug("MFA grace satisfied via cookie for client {ClientId} using {Method} exp {Exp}", clientId, method, expiration);
                                    }
                                }
                            }
                            catch (CryptographicException cex)
                            { context.Response.Cookies.Delete(cookieName); _logger.LogInformation(cex, "Invalid MFA grace cookie for {ClientId}", clientId); }
                            catch (Exception ex) { _logger.LogDebug(ex, "Grace cookie parse failed {ClientId}", clientId); }
                        }
                    }

                    if (!amrOk)
                    {
                        var originalAuthorizeUrl = context.Request.GetDisplayUrl();
                        bool userHasWebAuthn = await _context.WebAuthnCredentials.AnyAsync(c => c.UserId == authUser.Id);
                        bool userTotpEnabled = await _userManager.GetTwoFactorEnabledAsync(authUser);
                        var passkeyAllowed = allowedList.Any(m => m.Equals("fido2", StringComparison.OrdinalIgnoreCase) || m.Equals("passkey", StringComparison.OrdinalIgnoreCase));
                        var totpAllowed = allowedList.Any(m => m.Equals("totp", StringComparison.OrdinalIgnoreCase));
                        if (totpAllowed && userTotpEnabled) return Results.Redirect("/mfa/challenge?returnUrl=" + Uri.EscapeDataString(originalAuthorizeUrl));
                        if (passkeyAllowed && userHasWebAuthn) return Results.Redirect($"/connect/login?mode=passkey&returnUrl={Uri.EscapeDataString(originalAuthorizeUrl)}&clientId={Uri.EscapeDataString(clientId)}");
                        if (totpAllowed && !userTotpEnabled) return Results.Redirect("/mfa/setup?returnUrl=" + Uri.EscapeDataString(originalAuthorizeUrl));
                        if (passkeyAllowed) return Results.Redirect($"/connect/login?mode=passkey&returnUrl={Uri.EscapeDataString(originalAuthorizeUrl)}&clientId={Uri.EscapeDataString(clientId)}");
                        return Results.Redirect("/mfa/challenge?returnUrl=" + Uri.EscapeDataString(originalAuthorizeUrl));
                    }
                }
            }
        }
        catch (Exception ex) { _logger.LogWarning(ex, "MFA enforcement failed {ClientId}", clientId); }

        // Build principal
        var claimsIdentity = new ClaimsIdentity(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        var subClaim = new Claim(OpenIddictConstants.Claims.Subject, authUser.Id);
        subClaim.SetDestinations(OpenIddictConstants.Destinations.AccessToken, OpenIddictConstants.Destinations.IdentityToken);
        claimsIdentity.AddClaim(subClaim);
        var emailClaim = new Claim(OpenIddictConstants.Claims.Email, authUser.Email ?? string.Empty);
        emailClaim.SetDestinations(OpenIddictConstants.Destinations.AccessToken, OpenIddictConstants.Destinations.IdentityToken);
        claimsIdentity.AddClaim(emailClaim);
        var userNameClaimValue = await GetUserNameClaimAsync(authUser);
        var nameClaim = new Claim(OpenIddictConstants.Claims.Name, userNameClaimValue);
        nameClaim.SetDestinations(OpenIddictConstants.Destinations.AccessToken, OpenIddictConstants.Destinations.IdentityToken);
        claimsIdentity.AddClaim(nameClaim);
        var preferredUsernameClaim = new Claim(OpenIddictConstants.Claims.PreferredUsername, authUser.UserName ?? string.Empty);
        preferredUsernameClaim.SetDestinations(OpenIddictConstants.Destinations.AccessToken, OpenIddictConstants.Destinations.IdentityToken);
        claimsIdentity.AddClaim(preferredUsernameClaim);

        // NEW: ensure nonce claim is emitted in ID token when a nonce was supplied on the authorization request (URL or JAR)
        if (!string.IsNullOrWhiteSpace(request.Nonce))
        {
            var nonceClaim = new Claim(OpenIddictConstants.Claims.Nonce, request.Nonce!);
            nonceClaim.SetDestinations(OpenIddictConstants.Destinations.IdentityToken);
            // Do NOT add to access token (not needed there)
            claimsIdentity.AddClaim(nonceClaim);
        }

        await AddProfileClaimsAsync(claimsIdentity, authUser, request.GetScopes());
        var roles = await _userManager.GetRolesAsync(authUser);
        foreach (var role in roles)
        {
            var roleClaim = new Claim(OpenIddictConstants.Claims.Role, role);
            roleClaim.SetDestinations(OpenIddictConstants.Destinations.AccessToken, OpenIddictConstants.Destinations.IdentityToken);
            claimsIdentity.AddClaim(roleClaim);
        }

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
            else if (!string.IsNullOrEmpty(_mfaSatisfiedMethod))
            {
                var amrClaim = new Claim("amr", _mfaSatisfiedMethod);
                amrClaim.SetDestinations(OpenIddictConstants.Destinations.AccessToken, OpenIddictConstants.Destinations.IdentityToken);
                claimsIdentity.AddClaim(amrClaim);
            }
        }
        catch (Exception ex) { _logger.LogDebug(ex, "AMR propagation failed"); }

        var authPrincipal = new ClaimsPrincipal(claimsIdentity);
        authPrincipal.SetScopes(request.GetScopes());

        try
        {
            var dbClient = await _context.Clients.Include(c => c.Realm).FirstOrDefaultAsync(c => c.ClientId == clientId);
            if (dbClient != null)
            {
                authPrincipal.SetAuthorizationCodeLifetime(dbClient.GetEffectiveAuthorizationCodeLifetime());
            }
        }
        catch (Exception ex) { _logger.LogWarning(ex, "Failed to set code lifetime for {ClientId}", clientId); }

        if (!await _dynamicCookieService.IsAuthenticatedForClientAsync(clientId))
        {
            try { await _dynamicCookieService.SignInWithClientCookieAsync(clientId, authUser, false); } catch { }
        }

        _logger.LogDebug("Authorization granted for user {UserName} and client {ClientId}", authUser.UserName, clientId);
        return Results.SignIn(authPrincipal, authenticationScheme: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }

    private async Task<object?> ValidateAndApplyJarAsync(Client dbClient, string requestJwt, OpenIddictRequest request, HttpContext httpContext)
    {
        var opts = _jarOptions.Value;
        // Quick structural check
        if (requestJwt.Count(c => c == '.') != 2)
            return new { error = OpenIddictConstants.Errors.InvalidRequestObject, error_description = "request object must be JWT" };

        // Determine allowed algorithms
        var allowedCsv = dbClient.AllowedRequestObjectAlgs;
        var allowed = string.IsNullOrWhiteSpace(allowedCsv)
            ? new HashSet<string>(StringComparer.OrdinalIgnoreCase) { SecurityAlgorithms.RsaSha256, SecurityAlgorithms.HmacSha256 }
            : allowedCsv.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).ToHashSet(StringComparer.OrdinalIgnoreCase);

        var handler = new JwtSecurityTokenHandler();
        JwtSecurityToken token;
        try { token = handler.ReadJwtToken(requestJwt); }
        catch (Exception ex) { _logger.LogInformation(ex, "Failed to parse JAR for {ClientId}", dbClient.ClientId); return new { error = OpenIddictConstants.Errors.InvalidRequestObject, error_description = "invalid request object" }; }

        var alg = token.Header.Alg;
        if (!allowed.Contains(alg))
            return new { error = OpenIddictConstants.Errors.InvalidRequestObject, error_description = "unsupported alg" };
        if ((dbClient.RequireSignedRequestObject ?? true) && alg == SecurityAlgorithms.None)
            return new { error = OpenIddictConstants.Errors.InvalidRequestObject, error_description = "unsigned not allowed" };

        // Validate signature (best-effort) for HS256 / RS256
        try
        {
            var parameters = new TokenValidationParameters
            {
                ValidateAudience = false,
                ValidateIssuer = false,
                ValidateLifetime = true,
                ClockSkew = TimeSpan.FromSeconds(30),
                RequireSignedTokens = true,
                ValidateIssuerSigningKey = true
            };
            if (alg.StartsWith("HS", StringComparison.OrdinalIgnoreCase))
            {
                var plainSecret = await _clientSecretService.GetActivePlaintextAsync(dbClient.ClientId, httpContext.RequestAborted);
                if (string.IsNullOrWhiteSpace(plainSecret) || Encoding.UTF8.GetByteCount(plainSecret) < 32)
                    return new { error = OpenIddictConstants.Errors.InvalidRequestObject, error_description = "client secret length below policy" };
                parameters.IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(plainSecret));
            }
            else if (alg.StartsWith("RS", StringComparison.OrdinalIgnoreCase))
            {
                var (signing, _) = await _keyService.GetActiveKeysAsync();
                parameters.IssuerSigningKeys = signing;
            }
            else
            {
                return new { error = OpenIddictConstants.Errors.InvalidRequestObject, error_description = "alg not supported" };
            }
            var jsonHandler = new JsonWebTokenHandler();
            var validateResult = await jsonHandler.ValidateTokenAsync(requestJwt, parameters);
            if (!validateResult.IsValid)
            {
                _logger.LogInformation(validateResult.Exception, "Signature validation failed for JAR {ClientId}", dbClient.ClientId);
                return new { error = OpenIddictConstants.Errors.InvalidRequestObject, error_description = "signature invalid" };
            }
        }
        catch (Exception ex)
        {
            _logger.LogInformation(ex, "Signature validation failed for JAR {ClientId}", dbClient.ClientId);
            return new { error = OpenIddictConstants.Errors.InvalidRequestObject, error_description = "signature invalid" };
        }

        var now = DateTimeOffset.UtcNow;
        // exp claim (avoid obsolete Exp property)
        DateTimeOffset? exp = null;
        if (token.Payload.TryGetValue("exp", out var expObj) && long.TryParse(expObj.ToString(), out var expSec))
        {
            try { exp = DateTimeOffset.FromUnixTimeSeconds(expSec); } catch { exp = null; }
        }
        if (exp is null || exp < now || exp > now.Add(opts.MaxExp))
            return new { error = OpenIddictConstants.Errors.InvalidRequestObject, error_description = "exp invalid" };

        if (token.Payload.TryGetValue("iat", out var iatObj) && long.TryParse(iatObj.ToString(), out var iatSec))
        {
            var iat = DateTimeOffset.FromUnixTimeSeconds(iatSec);
            if (iat < now.Add(-opts.MaxExp) || iat > now.Add(opts.ClockSkew))
                return new { error = OpenIddictConstants.Errors.InvalidRequestObject, error_description = "iat invalid" };
        }

        // JTI replay protection
        if (opts.RequireJti)
        {
            if (!token.Payload.TryGetValue("jti", out var jtiObj) || string.IsNullOrWhiteSpace(jtiObj?.ToString()))
            {
                return new { error = OpenIddictConstants.Errors.InvalidRequestObject, error_description = "jti required" };
            }
            var jti = jtiObj!.ToString()!;
            if (!_jarReplayCache.TryAdd("jar:jti:" + jti, exp ?? now.Add(opts.JtiCacheWindow)))
            {
                return new { error = OpenIddictConstants.Errors.InvalidRequestObject, error_description = "jti replay" };
            }
        }

        string? Get(string name) => token.Payload.TryGetValue(name, out var v) ? v?.ToString() : null;
        void CheckMismatch(string paramName, string? jwtValue, string? urlValue)
        {
            if (string.IsNullOrEmpty(jwtValue) || string.IsNullOrEmpty(urlValue)) return;
            if (!string.Equals(jwtValue, urlValue, StringComparison.Ordinal))
                throw new InvalidOperationException($"parameter mismatch: {paramName}");
        }
        try
        {
            CheckMismatch("scope", Get(OpenIddictConstants.Parameters.Scope), request.Scope);
            CheckMismatch("redirect_uri", Get(OpenIddictConstants.Parameters.RedirectUri), request.RedirectUri);
            CheckMismatch("response_type", Get(OpenIddictConstants.Parameters.ResponseType), request.ResponseType);
            CheckMismatch("state", Get(OpenIddictConstants.Parameters.State), request.State);
            CheckMismatch("nonce", Get(OpenIddictConstants.Parameters.Nonce), request.Nonce); // NEW: ensure nonce consistency
        }
        catch (InvalidOperationException mis)
        {
            return new { error = OpenIddictConstants.Errors.InvalidRequest, error_description = mis.Message };
        }

        // Apply precedence from request object
        var scopeJwt = Get(OpenIddictConstants.Parameters.Scope);
        if (!string.IsNullOrEmpty(scopeJwt)) request.Scope = scopeJwt;
        var redirectJwt = Get(OpenIddictConstants.Parameters.RedirectUri);
        if (!string.IsNullOrEmpty(redirectJwt)) request.RedirectUri = redirectJwt;
        var respTypeJwt = Get(OpenIddictConstants.Parameters.ResponseType);
        if (!string.IsNullOrEmpty(respTypeJwt)) request.ResponseType = respTypeJwt;
        var stateJwt = Get(OpenIddictConstants.Parameters.State);
        if (!string.IsNullOrEmpty(stateJwt)) request.State = stateJwt;
        var nonceJwt = Get(OpenIddictConstants.Parameters.Nonce); // NEW
        if (!string.IsNullOrEmpty(nonceJwt)) request.Nonce = nonceJwt; // NEW preserve nonce for ID token

        return null; // success
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

    private async Task SafeSignOutClientAsync(string clientId)
    { try { await _dynamicCookieService.SignOutFromClientAsync(clientId); } catch (Exception ex) { _logger.LogWarning(ex, "Failed sign out client cookie {ClientId}", clientId); } }

    private async Task<string> GetUserNameClaimAsync(IdentityUser user)
    {
        try
        {
            var claims = await _userManager.GetClaimsAsync(user);
            var nameClaim = claims.FirstOrDefault(c => c.Type == "name")?.Value;
            if (!string.IsNullOrEmpty(nameClaim)) return nameClaim;
        }
        catch (Exception ex) { _logger.LogError(ex, "Error retrieving name claim for {UserId}", user.Id); }
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
        catch (Exception ex) { _logger.LogError(ex, "Error retrieving profile claims for user {UserId}", user.Id); }
    }

    private string ConvertToFriendlyName(string input)
    {
        if (string.IsNullOrEmpty(input)) return "Unknown User";
        var friendlyName = input.Replace('.', ' ').Replace('_', ' ').Replace('-', ' ');
        var words = friendlyName.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        var capitalizedWords = words.Select(word => word.Length > 0 ? char.ToUpper(word[0]) + word.Substring(1).ToLower() : word);
        return string.Join(" ", capitalizedWords);
    }
}