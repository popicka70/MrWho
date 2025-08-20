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
            // Ensure local cookies are cleared before delegating to OpenIddict
            await SignOutLocalAsync(http, clientId);
            DeleteAllKnownAuthCookies(http);
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

        await SignOutLocalAsync(http, clientId);
        DeleteAllKnownAuthCookies(http);

        return new RedirectToActionResult("Index", "Home", new { logout = "success" });
    }

    private async Task SignOutLocalAsync(HttpContext http, string? clientId)
    {
        await _signInManager.SignOutAsync();
        DeleteCookieAcrossDomains(http, ".AspNetCore.Identity.Application");

        string? detectedClientId = clientId;
        if (!string.IsNullOrEmpty(detectedClientId))
        {
            try
            {
                await _dynamicCookieService.SignOutFromClientAsync(detectedClientId);
                var cookieName = _cookieService.GetCookieNameForClient(detectedClientId);
                DeleteCookieAcrossDomains(http, cookieName);
            }
            catch (Exception ex) { _logger.LogWarning(ex, "Failed to sign out from client-specific cookie for client {ClientId}", detectedClientId); }
        }
        else
        {
            // Restore previous behavior: iterate all configured client cookies when we cannot detect a specific client.
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
                // Best-effort clear of currently present cookies if client is unknown
                DeleteAllKnownAuthCookies(http);
            }
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

    private void DeleteAllKnownAuthCookies(HttpContext http)
    {
        try
        {
            DeleteCookieAcrossDomains(http, ".AspNetCore.Identity.Application");
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
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Failed to enumerate/delete known auth cookies");
        }
    }
}
