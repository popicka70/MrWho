using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Fido2NetLib;
using Fido2NetLib.Objects;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;
using MrWho.Data;
using MrWho.Models;
using MrWho.Services;

namespace MrWho.Controllers;

[Route("webauthn")]
public class WebAuthnController : Controller
{
    private readonly Fido2 _fido2;
    private readonly ApplicationDbContext _db;
    private readonly UserManager<IdentityUser> _userManager;
    private static readonly Dictionary<string, CredentialCreateOptions> _attestationOptions = new();
    private static readonly Dictionary<string, AssertionOptions> _assertionOptions = new();
    private readonly ILogger<WebAuthnController> _logger;
    private readonly string _rpId;
    private readonly string _rpName;
    private readonly IUserRealmValidationService _realmValidationService; // added
    private readonly IDynamicCookieService _dynamicCookieService; // added
    private readonly ITimeLimitedDataProtector _mfaProtector; // for grace cookie
    private const string MfaCookiePrefix = ".MrWho.Mfa.";

    public WebAuthnController(
        IConfiguration config,
        ApplicationDbContext db,
        UserManager<IdentityUser> userManager,
        ILogger<WebAuthnController> logger,
        IUserRealmValidationService realmValidationService, // added
        IDynamicCookieService dynamicCookieService, // added
        IDataProtectionProvider dataProtectionProvider
        )
    {
        _db = db;
        _userManager = userManager;
        _logger = logger;
        _realmValidationService = realmValidationService; // added
        _dynamicCookieService = dynamicCookieService; // added
        _mfaProtector = dataProtectionProvider.CreateProtector("MrWho.MfaCookie").ToTimeLimitedDataProtector();

        _rpId = config["WebAuthn:RelyingPartyId"] ?? new Uri(config["OpenIddict:Issuer"] ?? "https://localhost:7113").Host;
        _rpName = config["WebAuthn:RelyingPartyName"] ?? "MrWho";
        _fido2 = new Fido2(new Fido2Configuration
        {
            ServerDomain = _rpId,
            ServerName = _rpName,
            Origins = GetOrigins(config)
        });
    }

    private static HashSet<string> GetOrigins(IConfiguration config)
    {
        var origins = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var fromConfig = config.GetSection("WebAuthn:Origins").Get<string[]>() ?? Array.Empty<string>();
        foreach (var o in fromConfig)
        {
            if (!string.IsNullOrWhiteSpace(o)) origins.Add(o);
        }
        // sensible dev defaults
        origins.Add("https://localhost:7113");
        origins.Add("http://localhost:7113");
        return origins;
    }

    // Interactive WebAuthn login page: auto-starts assertion and redirects
    [HttpGet("login")]
    [AllowAnonymous]
    public IActionResult Login([FromQuery] string? returnUrl = null, [FromQuery] string? clientId = null)
    {
        ViewData["ReturnUrl"] = returnUrl;
        ViewData["ClientId"] = clientId;
        return View("Login");
    }

    // ===== Registration: options =====
    [HttpGet("register/options")]
    [Authorize]
    public async Task<IActionResult> GetRegisterOptions([FromQuery] string? nickname = null)
    {
        var user = await _userManager.GetUserAsync(User);
        if (user == null) return Unauthorized();
        var userId = Encoding.UTF8.GetBytes(user.Id);

        // Exclude already-registered credentials
        var creds = await _db.WebAuthnCredentials.Where(c => c.UserId == user.Id).ToListAsync();
        var exclude = creds.Select(c => new PublicKeyCredentialDescriptor(WebEncoders.Base64UrlDecode(c.CredentialId))).ToList();

        var fidoUser = new Fido2User
        {
            Id = userId,
            Name = user.Email ?? user.UserName ?? user.Id,
            DisplayName = await _userManager.GetUserNameAsync(user) ?? user.Email ?? user.Id
        };

        var authSel = new AuthenticatorSelection
        {
            ResidentKey = ResidentKeyRequirement.Required,
            UserVerification = UserVerificationRequirement.Required
        };

        // Request options using dynamic to tolerate overload differences across versions
        CredentialCreateOptions options;
        dynamic f = _fido2;
        try { options = f.RequestNewCredential(fidoUser, exclude, authSel, AttestationConveyancePreference.None, null); }
        catch
        {
            try { options = f.RequestNewCredential(fidoUser, exclude, authSel, AttestationConveyancePreference.None); }
            catch { options = f.RequestNewCredential(fidoUser, exclude); }
        }

        _attestationOptions[user.Id] = options;
        return Json(options);
    }

    // ===== Registration: verify =====
    [HttpPost("register/verify")]
    [Authorize]
    public async Task<IActionResult> PostRegisterVerify([FromBody] AuthenticatorAttestationRawResponse attestationResponse)
    {
        var user = await _userManager.GetUserAsync(User);
        if (user == null) return Unauthorized();
        if (!_attestationOptions.TryGetValue(user.Id, out var options)) return BadRequest("No options for user");

        dynamic res;
        var f = (dynamic)_fido2;
        try
        {
            res = await f.MakeNewCredentialAsync(attestationResponse, options, (Func<dynamic, System.Threading.CancellationToken, Task<bool>>)(async (args, ct) =>
            {
                // compute ID once to avoid dynamic inside EF expression tree
                string id = WebEncoders.Base64UrlEncode((byte[])args.CredentialId);
                return !await _db.WebAuthnCredentials.AnyAsync(c => c.CredentialId == id, ct);
            }), HttpContext.RequestAborted);
        }
        catch
        {
            try
            {
                res = await f.MakeNewCredentialAsync(attestationResponse, options, (Func<dynamic, System.Threading.CancellationToken, Task<bool>>)(async (args, ct) =>
                {
                    string id = WebEncoders.Base64UrlEncode((byte[])args.CredentialId);
                    return !await _db.WebAuthnCredentials.AnyAsync(c => c.CredentialId == id, ct);
                }));
            }
            catch
            {
                res = await f.MakeNewCredentialAsync(attestationResponse, options);
            }
        }

        // Extract attestation info when available
        string? aaGuid = null;
        string? fmt = null;
        try
        {
            var resResult = res?.Result;
            if (resResult != null)
            {
                try
                {
                    aaGuid = (resResult.Aaguid is Guid g) ? g.ToString() : resResult.Aaguid?.ToString();
                }
                catch { }
                try { fmt = resResult.Fmt?.ToString(); } catch { }
            }
        }
        catch { }

        var cred = new WebAuthnCredential
        {
            UserId = user.Id,
            CredentialId = res?.Result?.CredentialId is byte[] cid ? WebEncoders.Base64UrlEncode(cid) : string.Empty,
            PublicKey = res?.Result?.PublicKey is byte[] pk ? WebEncoders.Base64UrlEncode(pk) : string.Empty,
            UserHandle = res?.Result?.User?.Id is byte[] uid ? WebEncoders.Base64UrlEncode(uid) : string.Empty,
            SignCount = 0,
            AaGuid = aaGuid,
            AttestationFmt = fmt,
            IsDiscoverable = true,
            Nickname = null
        };
        if (string.IsNullOrEmpty(cred.CredentialId) || string.IsNullOrEmpty(cred.PublicKey) || string.IsNullOrEmpty(cred.UserHandle))
        {
            return BadRequest(new { ok = false, error = "Invalid attestation result" });
        }
        _db.WebAuthnCredentials.Add(cred);
        await _db.SaveChangesAsync();

        _attestationOptions.Remove(user.Id);
        return Json(new { ok = true });
    }

    // ===== Authentication: options =====
    [HttpGet("login/options")]
    [AllowAnonymous]
    public async Task<IActionResult> GetLoginOptions([FromQuery] string? email = null)
    {
        // If email provided and user has non-discoverable credentials, set allowCredentials; otherwise allow discoverable
        List<PublicKeyCredentialDescriptor> allowCredentials = new List<PublicKeyCredentialDescriptor>();
        if (!string.IsNullOrEmpty(email))
        {
            var user = await _userManager.FindByNameAsync(email) ?? await _userManager.FindByEmailAsync(email);
            if (user != null)
            {
                var creds = await _db.WebAuthnCredentials.Where(c => c.UserId == user.Id).ToListAsync();
                if (creds.Count > 0)
                {
                    allowCredentials = creds.Select(c => new PublicKeyCredentialDescriptor(WebEncoders.Base64UrlDecode(c.CredentialId))).ToList();
                }
            }
        }

        var options = _fido2.GetAssertionOptions(allowCredentials, UserVerificationRequirement.Required);
        var key = HttpContext.Session.Id; // session-bound nonce bucket
        _assertionOptions[key] = options;
        return Json(options);
    }

    // ===== Authentication: verify =====
    [HttpPost("login/verify")]
    [AllowAnonymous]
    public async Task<IActionResult> PostLoginVerify([FromBody] AuthenticatorAssertionRawResponse clientResponse, [FromQuery] string? returnUrl = null, [FromQuery] string? clientId = null)
    {
        var key = HttpContext.Session.Id;
        if (!_assertionOptions.TryGetValue(key, out var options)) return BadRequest("No assertion options in session");

        async Task<dynamic> VerifyAsync()
        {
            // 1) Find the credential by id
            var credentialId = clientResponse.Id;
            var cred = await _db.WebAuthnCredentials.FirstOrDefaultAsync(c => c.CredentialId == credentialId);
            if (cred == null) throw new InvalidOperationException("Unknown credential");

            // 2) Get stored public key and counter
            var storedPublicKey = WebEncoders.Base64UrlDecode(cred.PublicKey);
            var storedCounter = cred.SignCount;

            dynamic res;
            var f = (dynamic)_fido2;
            try
            {
                res = await f.MakeAssertionAsync(clientResponse, options, storedPublicKey, storedCounter, (Func<dynamic, System.Threading.CancellationToken, Task<bool>>)((args, ct) => Task.FromResult(true)));
            }
            catch
            {
                try { res = await f.MakeAssertionAsync(clientResponse, options, storedPublicKey, storedCounter); }
                catch { res = await f.MakeAssertionAsync(clientResponse, options); }
            }

            // 4) Update counter (cast to uint as model uses uint)
            cred.SignCount = (uint)res.Counter;
            await _db.SaveChangesAsync();

            return res;
        }

        try
        {
            var result = await VerifyAsync();
            // Get user and sign-in
            var credId = clientResponse.Id;
            var cred = await _db.WebAuthnCredentials.FirstAsync(c => c.CredentialId == credId);
            var user = await _userManager.FindByIdAsync(cred.UserId);
            if (user == null) return Unauthorized();

            // Eligibility validation BEFORE sign-in or client cookie
            if (!string.IsNullOrEmpty(clientId))
            {
                try
                {
                    var validation = await _realmValidationService.ValidateUserRealmAccessAsync(user, clientId);
                    if (!validation.IsValid)
                    {
                        _logger.LogWarning("WebAuthn login denied: user {User} not eligible for client {ClientId}. Reason: {Reason}", user.UserName, clientId, validation.Reason);
                        _assertionOptions.Remove(key);
                        return Redirect(BuildAccessDeniedUrl(returnUrl, clientId));
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error validating eligibility for user {User} and client {ClientId} during WebAuthn verify", user.Id, clientId);
                    _assertionOptions.Remove(key);
                    return Redirect(BuildAccessDeniedUrl(returnUrl, clientId));
                }
            }

            // Passwordless sign-in with amr=fido2
            await HttpContext.SignOutAsync(IdentityConstants.TwoFactorUserIdScheme); // ensure clean
            await HttpContext.SignOutAsync(IdentityConstants.ApplicationScheme);

            await _userManager.UpdateSecurityStampAsync(user);
            await HttpContext.SignInAsync(IdentityConstants.ApplicationScheme, await BuildPrincipalAsync(user, "fido2"));

            // Client-specific cookie only after eligibility validation
            if (!string.IsNullOrEmpty(clientId))
            {
                try
                {
                    await _dynamicCookieService.SignInWithClientCookieAsync(clientId, user, rememberMe: true);

                    // Set MFA grace cookie if client/realm allows remembering MFA
                    var dbClient = await _db.Clients.Include(c => c.Realm).FirstOrDefaultAsync(c => c.ClientId == clientId);
                    if (dbClient != null)
                    {
                        var remember = dbClient.RememberMfaForSession ?? dbClient.Realm?.DefaultRememberMfaForSession ?? true;
                        var graceMinutes = dbClient.MfaGracePeriodMinutes ?? dbClient.Realm?.DefaultMfaGracePeriodMinutes ?? 60;
                        if (remember && graceMinutes > 0)
                        {
                            var payload = $"v1|fido2|{DateTimeOffset.UtcNow.ToUnixTimeSeconds()}";
                            var protectedValue = _mfaProtector.Protect(payload, lifetime: TimeSpan.FromMinutes(graceMinutes));
                            var cookieName = MfaCookiePrefix + clientId;
                            Response.Cookies.Append(cookieName, protectedValue, new CookieOptions
                            {
                                HttpOnly = true,
                                Secure = true,
                                SameSite = SameSiteMode.Lax,
                                Expires = DateTimeOffset.UtcNow.AddMinutes(graceMinutes),
                                IsEssential = true
                            });
                        }
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Failed client-specific cookie sign-in for client {ClientId}", clientId);
                }
            }

            _assertionOptions.Remove(key);

            if (!string.IsNullOrEmpty(returnUrl))
            {
                if (Url.IsLocalUrl(returnUrl) || returnUrl.Contains("/connect/authorize", StringComparison.OrdinalIgnoreCase))
                    return Redirect(returnUrl);
            }
            return Redirect("/");
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "WebAuthn login verify failed");
            return BadRequest(new { ok = false, error = ex.Message });
        }
    }

    private async Task<ClaimsPrincipal> BuildPrincipalAsync(IdentityUser user, string authenticationMethod)
    {
        var claims = new List<Claim>
        {
            new Claim(ClaimTypes.NameIdentifier, user.Id),
            new Claim(ClaimTypes.Name, user.UserName ?? user.Email ?? user.Id),
            new Claim("amr", authenticationMethod)
        };

        var identity = new ClaimsIdentity(claims, IdentityConstants.ApplicationScheme);
        var principal = new ClaimsPrincipal(identity);
        await Task.CompletedTask;
        return principal;
    }

    private static string BuildAccessDeniedUrl(string? returnUrl, string? clientId)
    {
        var ret = !string.IsNullOrEmpty(returnUrl) ? Uri.EscapeDataString(returnUrl) : string.Empty;
        var cid = !string.IsNullOrEmpty(clientId) ? Uri.EscapeDataString(clientId) : string.Empty;
        var url = "/connect/access-denied";
        var hasQuery = false;
        if (!string.IsNullOrEmpty(ret)) { url += $"?returnUrl={ret}"; hasQuery = true; }
        if (!string.IsNullOrEmpty(cid)) { url += hasQuery ? $"&clientId={cid}" : $"?clientId={cid}"; }
        return url;
    }
}
