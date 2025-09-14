using Microsoft.AspNetCore; // for OpenIddict HttpContext extension visibility
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using OpenIddict.Client.AspNetCore;

namespace MrWho.Services;

public interface ILogoutHelper
{
    bool UseGlobalLogout(HttpContext http);
    bool IsOidcLogoutRequest(HttpContext http);
    Task<string?> TryGetClientIdFromRequestAsync(HttpContext http);
    Task SignOutClientOnlyAsync(HttpContext http, string? clientId);
    Task SignOutGlobalAsync(HttpContext http, string? initiatingClientId);
    void DeleteCookieAcrossDomains(HttpContext http, string cookieName);
}

public sealed class LogoutHelper : ILogoutHelper
{
    private readonly ILogger<LogoutHelper> _logger;
    private readonly IConfiguration _configuration;
    private readonly SignInManager<IdentityUser> _signInManager;
    private readonly IClientCookieConfigurationService _cookieService;
    private readonly IDynamicCookieService _dynamicCookieService;

    public LogoutHelper(
        ILogger<LogoutHelper> logger,
        IConfiguration configuration,
        SignInManager<IdentityUser> signInManager,
        IClientCookieConfigurationService cookieService,
        IDynamicCookieService dynamicCookieService)
    {
        _logger = logger;
        _configuration = configuration;
        _signInManager = signInManager;
        _cookieService = cookieService;
        _dynamicCookieService = dynamicCookieService;
    }

    public bool UseGlobalLogout(HttpContext http)
    {
        var scope = _configuration["Logout:Scope"]; // Global | Client (default Client)
        if (!string.IsNullOrWhiteSpace(scope) && scope.Equals("Global", StringComparison.OrdinalIgnoreCase))
        {
            _logger.LogDebug("Logout scope set to GLOBAL by configuration");
            return true;
        }
        _logger.LogDebug("Logout scope set to CLIENT (default)");
        return false;
    }

    public bool IsOidcLogoutRequest(HttpContext http)
    {
        try
        {
            var oidcReq = http.GetOpenIddictServerRequest();
            return oidcReq != null && (!string.IsNullOrEmpty(oidcReq.IdTokenHint)
                                     || !string.IsNullOrEmpty(oidcReq.PostLogoutRedirectUri)
                                     || !string.IsNullOrEmpty(oidcReq.ClientId)
                                     || !string.IsNullOrEmpty(oidcReq.State));
        }
        catch
        {
            return false;
        }
    }

    public Task<string?> TryGetClientIdFromRequestAsync(HttpContext http)
    {
        Func<string?> getClientId = () =>
        {
            try
            {
                var req = http.GetOpenIddictServerRequest();
                if (!string.IsNullOrEmpty(req?.ClientId)) {
                    return req.ClientId;
                }

                var query = http.Request.Query["client_id"].ToString();
                if (!string.IsNullOrEmpty(query)) {
                    return query;
                }

                var form = http.Request.HasFormContentType ? http.Request.Form["client_id"].ToString() : null;
                if (!string.IsNullOrEmpty(form)) {
                    return form;
                }
            }
            catch { }
            return null;
        };
        return Task.FromResult(getClientId());
    }

    public async Task SignOutClientOnlyAsync(HttpContext http, string? clientId)
    {
        try
        {
            string? detectedClientId = clientId ?? await TryGetClientIdFromRequestAsync(http);

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

    public async Task SignOutGlobalAsync(HttpContext http, string? initiatingClientId)
    {
        try
        {
            await _signInManager.SignOutAsync();
            DeleteCookieAcrossDomains(http, ".AspNetCore.Identity.Application");

            if (!string.IsNullOrEmpty(initiatingClientId))
            {
                try
                {
                    await _dynamicCookieService.SignOutFromClientAsync(initiatingClientId);
                    var cookieName = _cookieService.GetCookieNameForClient(initiatingClientId);
                    DeleteCookieAcrossDomains(http, cookieName);
                }
                catch { }
            }

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

    public void DeleteCookieAcrossDomains(HttpContext http, string cookieName)
    {
        if (string.IsNullOrWhiteSpace(cookieName)) {
            return;
        }

        var configured = _configuration["Cookie:Domain"];
        var host = http.Request.Host.Host;
        var requireHttps = string.Equals(_configuration["Cookie:RequireHttps"], "true", StringComparison.OrdinalIgnoreCase);
        var secure = requireHttps || http.Request.IsHttps;

        var domains = new List<string?> { null };
        if (!string.IsNullOrWhiteSpace(host))
        {
            domains.Add(host);
            if (!host.StartsWith('.')) {
                domains.Add("." + host);
            }
        }
        if (!string.IsNullOrWhiteSpace(configured))
        {
            domains.Add(configured);
            if (!configured.StartsWith('.')) {
                domains.Add("." + configured);
            }
        }

        foreach (var d in domains.Distinct(StringComparer.OrdinalIgnoreCase))
        {
            try
            {
                http.Response.Cookies.Delete(cookieName, new CookieOptions
                {
                    Path = "/",
                    Domain = d,
                    HttpOnly = true,
                    Secure = secure,
                    SameSite = SameSiteMode.None
                });
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Error deleting cookie {Cookie} for domain {Domain}", cookieName, d ?? "<null>");
            }
        }
    }
}
