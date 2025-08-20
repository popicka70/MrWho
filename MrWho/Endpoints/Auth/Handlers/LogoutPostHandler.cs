using Microsoft.AspNetCore; // for OpenIddict HttpContext extensions
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using MrWho.Services;
using MrWho.Services.Mediator;
using OpenIddict.Client.AspNetCore;
using OpenIddict.Server.AspNetCore;

namespace MrWho.Endpoints.Auth;

public sealed class LogoutPostHandler : IRequestHandler<LogoutPostRequest, IActionResult>
{
    private readonly ILogger<LogoutPostHandler> _logger;
    private readonly SignInManager<IdentityUser> _signInManager;
    private readonly IClientCookieConfigurationService _cookieService;
    private readonly IDynamicCookieService _dynamicCookieService;
    private readonly IConfiguration _configuration;

    public LogoutPostHandler(ILogger<LogoutPostHandler> logger, SignInManager<IdentityUser> signInManager, IClientCookieConfigurationService cookieService, IDynamicCookieService dynamicCookieService, IConfiguration configuration)
    {
        _logger = logger;
        _signInManager = signInManager;
        _cookieService = cookieService;
        _dynamicCookieService = dynamicCookieService;
        _configuration = configuration;
    }

    public async Task<IActionResult> Handle(LogoutPostRequest request, CancellationToken cancellationToken)
    {
        var http = request.HttpContext;
        var clientId = request.ClientId;
        var postUri = request.PostLogoutRedirectUri;

        _logger.LogInformation("POST /connect/logout accessed. ClientId: {ClientId}, PostLogoutUri: {PostLogoutUri}", clientId, postUri);
        var oidcReq = http.GetOpenIddictServerRequest();
        bool isOidcLogoutRequest = oidcReq != null && (!string.IsNullOrEmpty(oidcReq.IdTokenHint) || !string.IsNullOrEmpty(oidcReq.PostLogoutRedirectUri) || !string.IsNullOrEmpty(oidcReq.ClientId) || !string.IsNullOrEmpty(oidcReq.State));
        if (isOidcLogoutRequest)
        {
            if (UseGlobalLogout(http))
            {
                await SignOutGlobalAsync(http, clientId);
            }
            else
            {
                await SignOutClientOnlyAsync(http, clientId);
            }
            return new SignOutResult(new[] { OpenIddictServerAspNetCoreDefaults.AuthenticationScheme });
        }

        // Direct (non-OIDC) logout: we can try session then claim fallback
        var externalRegId = http.Session.GetString("ExternalRegistrationId");
        if (string.IsNullOrWhiteSpace(externalRegId))
        {
            externalRegId = http.User?.FindFirst("ext_reg_id")?.Value;
        }
        if (!string.IsNullOrWhiteSpace(externalRegId))
        {
            _logger.LogInformation("External RegistrationId found during POST logout. Initiating external provider sign-out before local logout.");
            var props = new AuthenticationProperties { RedirectUri = "/connect/external/signout-callback" };
            props.Items[OpenIddictClientAspNetCoreConstants.Properties.RegistrationId] = externalRegId;
            await http.SignOutAsync(OpenIddictClientAspNetCoreDefaults.AuthenticationScheme, props);
            return new EmptyResult();
        }

        if (UseGlobalLogout(http))
        {
            await SignOutGlobalAsync(http, clientId);
        }
        else
        {
            await SignOutClientOnlyAsync(http, clientId);
        }

        return new RedirectToActionResult("Index", "Home", new { logout = "success" });
    }

    private bool UseGlobalLogout(HttpContext http)
    {
        // Config flag: Logout:Scope = Global | Client (default Client)
        var scope = _configuration["Logout:Scope"]; // e.g. appsettings.json or environment
        if (!string.IsNullOrWhiteSpace(scope) && scope.Equals("Global", StringComparison.OrdinalIgnoreCase))
        {
            _logger.LogDebug("Logout scope set to GLOBAL by configuration");
            return true;
        }
        _logger.LogDebug("Logout scope set to CLIENT (default)");
        return false;
    }

    // Signs out only the specified client's cookie/session. Preserves other clients' sessions.
    private async Task SignOutClientOnlyAsync(HttpContext http, string? clientId)
    {
        try
        {
            // Determine client id if not provided
            string? detectedClientId = clientId;
            if (string.IsNullOrEmpty(detectedClientId))
            {
                try
                {
                    var req = http.GetOpenIddictServerRequest();
                    if (!string.IsNullOrEmpty(req?.ClientId)) detectedClientId = req.ClientId;
                    else if (http.Request.Query.TryGetValue("client_id", out var cid) && !string.IsNullOrEmpty(cid)) detectedClientId = cid!;
                }
                catch { /* ignore */ }
            }

            if (!string.IsNullOrEmpty(detectedClientId))
            {
                await _dynamicCookieService.SignOutFromClientAsync(detectedClientId);
                var cookieName = _cookieService.GetCookieNameForClient(detectedClientId);
                DeleteCookieAcrossDomains(http, cookieName);
                _logger.LogInformation("Signed out from client-specific session only for {ClientId}", detectedClientId);
            }
            else
            {
                _logger.LogWarning("Could not detect clientId for logout request; preserving other clients by not clearing all cookies.");
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Error during client-only sign-out");
        }
    }

    // Signs out from default Identity cookie and clears all known client cookies
    private async Task SignOutGlobalAsync(HttpContext http, string? clientId)
    {
        try
        {
            await _signInManager.SignOutAsync();
            DeleteCookieAcrossDomains(http, ".AspNetCore.Identity.Application");

            // Clear the initiating client's cookie (if any)
            if (!string.IsNullOrEmpty(clientId))
            {
                try
                {
                    await _dynamicCookieService.SignOutFromClientAsync(clientId);
                    var cookieName = _cookieService.GetCookieNameForClient(clientId);
                    DeleteCookieAcrossDomains(http, cookieName);
                }
                catch {}
            }

            // Also clear any other known client cookies present on the request
            var configs = _cookieService.GetAllClientConfigurations();
            if (configs.Count > 0)
            {
                foreach (var kvp in configs)
                {
                    try { await _dynamicCookieService.SignOutFromClientAsync(kvp.Key); } catch { }
                    DeleteCookieAcrossDomains(http, kvp.Value.CookieName);
                }
            }
            else
            {
                // Best-effort: clear commonly named cookies
                DeleteCookieAcrossDomains(http, ".MrWho.Session");
                foreach (var kv in http.Request.Cookies)
                {
                    var name = kv.Key;
                    if (name.StartsWith(".MrWho", StringComparison.OrdinalIgnoreCase) ||
                        name.Contains("Identity.Application", StringComparison.OrdinalIgnoreCase) ||
                        name.Contains("Identity.External", StringComparison.OrdinalIgnoreCase) ||
                        name.StartsWith(".AspNetCore.Identity", StringComparison.OrdinalIgnoreCase))
                    {
                        DeleteCookieAcrossDomains(http, name);
                    }
                }
            }

            _logger.LogInformation("GLOBAL logout: cleared default and client cookies");
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Error during global sign-out");
        }
    }

    private void DeleteCookieAcrossDomains(HttpContext http, string cookieName)
    {
        if (string.IsNullOrWhiteSpace(cookieName)) return;
        var configured = _configuration["Cookie:Domain"];
        var host = http.Request.Host.Host;
        var requireHttps = string.Equals(_configuration["Cookie:RequireHttps"], "true", StringComparison.OrdinalIgnoreCase);
        var secure = requireHttps || http.Request.IsHttps;
        var domains = new List<string?> { null };
        if (!string.IsNullOrWhiteSpace(host))
        {
            domains.Add(host);
            if (!host.StartsWith('.')) domains.Add("." + host);
        }
        if (!string.IsNullOrWhiteSpace(configured))
        {
            domains.Add(configured);
            if (!configured.StartsWith('.')) domains.Add("." + configured);
        }
        foreach (var d in domains.Distinct(StringComparer.OrdinalIgnoreCase))
        {
            try { http.Response.Cookies.Delete(cookieName, new CookieOptions { Path = "/", Domain = d, HttpOnly = true, Secure = secure, SameSite = SameSiteMode.None }); }
            catch (Exception ex) { _logger.LogDebug(ex, "Error deleting cookie {Cookie} for domain {Domain}", cookieName, d ?? "<null>"); }
        }
    }
}
