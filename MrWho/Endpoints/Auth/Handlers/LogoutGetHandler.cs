using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ModelBinding;
using Microsoft.AspNetCore.Mvc.ViewFeatures;
using Microsoft.Extensions.Configuration;
using MrWho.Services;
using MrWho.Services.Mediator;
using OpenIddict.Abstractions;
using OpenIddict.Client.AspNetCore;
using OpenIddict.Server.AspNetCore;

namespace MrWho.Endpoints.Auth;

public sealed class LogoutGetHandler : IRequestHandler<LogoutGetRequest, IActionResult>
{
    private readonly SignInManager<IdentityUser> _signInManager;
    private readonly IClientCookieConfigurationService _cookieService;
    private readonly IDynamicCookieService _dynamicCookieService;
    private readonly IOpenIddictApplicationManager _applicationManager;
    private readonly ILogger<LogoutGetHandler> _logger;
    private readonly IConfiguration _configuration;

    public LogoutGetHandler(
        SignInManager<IdentityUser> signInManager,
        IClientCookieConfigurationService cookieService,
        IDynamicCookieService dynamicCookieService,
        IOpenIddictApplicationManager applicationManager,
        ILogger<LogoutGetHandler> logger,
        IConfiguration configuration)
    {
        _signInManager = signInManager;
        _cookieService = cookieService;
        _dynamicCookieService = dynamicCookieService;
        _applicationManager = applicationManager;
        _logger = logger;
        _configuration = configuration;
    }

    public async Task<IActionResult> Handle(LogoutGetRequest request, CancellationToken cancellationToken)
    {
        var http = request.HttpContext;
        var clientId = request.ClientId;
        var postUri = request.PostLogoutRedirectUri;

        _logger.LogInformation("GET /connect/logout accessed directly. ClientId: {ClientId}, PostLogoutUri: {PostLogoutUri}", clientId, postUri);
        var oidcReq = http.GetOpenIddictServerRequest();
        bool isOidcLogoutRequest = oidcReq != null && (!string.IsNullOrEmpty(oidcReq.IdTokenHint) || !string.IsNullOrEmpty(oidcReq.PostLogoutRedirectUri) || !string.IsNullOrEmpty(oidcReq.ClientId) || !string.IsNullOrEmpty(oidcReq.State));
        if (isOidcLogoutRequest)
        {
            return await ProcessLogoutInternalAsync(http, clientId, postUri, cancellationToken);
        }

        var externalRegId = http.Session.GetString("ExternalRegistrationId");
        if (!string.IsNullOrWhiteSpace(externalRegId))
        {
            _logger.LogInformation("External RegistrationId found in session during GET logout. Initiating external provider sign-out before local logout.");
            var returnAfterExternal = http.Request.Scheme + "://" + http.Request.Host + "/connect/logout" + new QueryString()
                .Add("clientId", clientId ?? string.Empty)
                .Add("post_logout_redirect_uri", postUri ?? string.Empty).ToUriComponent();
            http.Session.SetString("ExternalSignoutResumeUrl", returnAfterExternal ?? "/");

            var props = new AuthenticationProperties { RedirectUri = "/connect/external/signout-callback" };
            props.Items[OpenIddictClientAspNetCoreConstants.Properties.RegistrationId] = externalRegId;
            await http.SignOutAsync(OpenIddictClientAspNetCoreDefaults.AuthenticationScheme, props);
            return new EmptyResult();
        }

        _logger.LogInformation("Direct browser logout access detected (no OIDC parameters)");
        await _signInManager.SignOutAsync();
        DeleteCookieAcrossDomains(http, ".AspNetCore.Identity.Application");

        string? detectedClientId = clientId ?? await TryGetClientIdFromRequestAsync(http);
        if (!string.IsNullOrEmpty(detectedClientId))
        {
            try
            {
                await _dynamicCookieService.SignOutFromClientAsync(detectedClientId);
                var cookieName = _cookieService.GetCookieNameForClient(detectedClientId);
                DeleteCookieAcrossDomains(http, cookieName);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to sign out from client-specific cookie for client {ClientId}", detectedClientId);
            }
        }
        else
        {
            foreach (var kvp in _cookieService.GetAllClientConfigurations())
            {
                try { await _dynamicCookieService.SignOutFromClientAsync(kvp.Key); } catch { }
                DeleteCookieAcrossDomains(http, kvp.Value.CookieName);
            }
        }

        return new RedirectToActionResult("Index", "Home", new { logout = "success" });
    }

    private async Task<IActionResult> ProcessLogoutInternalAsync(HttpContext http, string? clientId, string? postLogoutUri, CancellationToken ct)
    {
        var request = http.GetOpenIddictServerRequest();
        string? detectedClientId = clientId ?? await TryGetClientIdFromRequestAsync(http);
        _logger.LogDebug("Processing OIDC logout. Method: {Method}, ClientId parameter: {ClientId}, Detected ClientId: {DetectedClientId}, Post logout URI: {PostLogoutUri}", http.Request.Method, clientId, detectedClientId, postLogoutUri ?? request?.PostLogoutRedirectUri);

        var externalRegId = http.Session.GetString("ExternalRegistrationId");
        if (!string.IsNullOrWhiteSpace(externalRegId))
        {
            _logger.LogInformation("External RegistrationId found in session. Initiating external provider sign-out before local logout.");
            var props = new AuthenticationProperties { RedirectUri = "/connect/external/signout-callback" };
            props.Items[OpenIddictClientAspNetCoreConstants.Properties.RegistrationId] = externalRegId;
            var resume = UriHelper.GetDisplayUrl(http.Request);
            http.Session.SetString("ExternalSignoutResumeUrl", resume ?? "/");
            await http.SignOutAsync(OpenIddictClientAspNetCoreDefaults.AuthenticationScheme, props);
            return new EmptyResult();
        }

        await SignOutFromAllSchemesAsync(http, detectedClientId);

        var candidateUri = postLogoutUri ?? request?.PostLogoutRedirectUri;
        var candidateClientId = clientId ?? request?.ClientId ?? detectedClientId;
        if (!string.IsNullOrEmpty(candidateUri))
        {
            var isValid = await IsPostLogoutRedirectUriValidAsync(candidateClientId, candidateUri);
            if (!isValid)
            {
                string? clientName = null;
                try
                {
                    if (!string.IsNullOrEmpty(candidateClientId))
                    {
                        var app = await _applicationManager.FindByClientIdAsync(candidateClientId);
                        if (app is not null) clientName = await _applicationManager.GetDisplayNameAsync(app);
                    }
                }
                catch { }

                var vd = new ViewDataDictionary(new EmptyModelMetadataProvider(), new ModelStateDictionary())
                {
                    ["ClientName"] = clientName,
                    ["ReturnUrl"] = null,
                    ["LogoutError"] = "You have been signed out, but the redirect URL provided by the application is invalid or not allowed."
                };
                return new ViewResult { ViewName = "LoggedOut", ViewData = vd };
            }
        }

        if (request != null)
        {
            return new SignOutResult(new[] { OpenIddictServerAspNetCoreDefaults.AuthenticationScheme });
        }

        return new RedirectToActionResult("Index", "Home", new { logout = "success" });
    }

    private async Task SignOutFromAllSchemesAsync(HttpContext http, string? clientId)
    {
        try
        {
            await _signInManager.SignOutAsync();
            DeleteCookieAcrossDomains(http, ".AspNetCore.Identity.Application");
            if (!string.IsNullOrEmpty(clientId))
            {
                try { await _dynamicCookieService.SignOutFromClientAsync(clientId); } catch (Exception ex) { _logger.LogWarning(ex, "Failed to sign out from client-specific cookie for client {ClientId}", clientId); }
                try { var cookieName = _cookieService.GetCookieNameForClient(clientId); DeleteCookieAcrossDomains(http, cookieName); } catch { }
            }
            else
            {
                var allConfigurations = _cookieService.GetAllClientConfigurations();
                foreach (var config in allConfigurations)
                {
                    try { await _dynamicCookieService.SignOutFromClientAsync(config.Key); } catch (Exception ex) { _logger.LogDebug(ex, "Failed to sign out from client configuration for client {ClientId}", config.Key); }
                    DeleteCookieAcrossDomains(http, config.Value.CookieName);
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during logout process");
        }
    }

    private void DeleteCookieAcrossDomains(HttpContext http, string cookieName)
    {
        if (string.IsNullOrWhiteSpace(cookieName)) return;
        try
        {
            http.Response.Cookies.Delete(cookieName, new CookieOptions{ Path = "/" });
            var configuredDomain = _configuration["Cookie:Domain"];
            if (!string.IsNullOrWhiteSpace(configuredDomain))
            {
                http.Response.Cookies.Delete(cookieName, new CookieOptions { Domain = configuredDomain, Path = "/" });
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Error deleting cookie {CookieName}", cookieName);
        }
    }

    private async Task<string?> TryGetClientIdFromRequestAsync(HttpContext http)
    {
        try
        {
            var request = http.GetOpenIddictServerRequest();
            if (!string.IsNullOrEmpty(request?.ClientId)) return request.ClientId;
            if (http.Request.Query.TryGetValue("client_id", out var clientIdFromQuery)) return clientIdFromQuery.ToString();
            var clientIdFromCookies = await _cookieService.GetClientIdFromRequestAsync(http);
            if (!string.IsNullOrEmpty(clientIdFromCookies)) return clientIdFromCookies;
            var referer = http.Request.Headers.Referer.ToString();
            if (!string.IsNullOrEmpty(referer) && referer.Contains("client_id="))
            {
                var uri = new Uri(referer);
                var query = System.Web.HttpUtility.ParseQueryString(uri.Query);
                var clientIdFromReferer = query["client_id"];
                if (!string.IsNullOrEmpty(clientIdFromReferer)) return clientIdFromReferer;
            }
            return null;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Error attempting to detect ClientId from request");
            return null;
        }
    }

    private async Task<bool> IsPostLogoutRedirectUriValidAsync(string? clientId, string? uri)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(uri)) return true;
            if (string.IsNullOrWhiteSpace(clientId)) return false;
            var application = await _applicationManager.FindByClientIdAsync(clientId);
            if (application is null) return false;
            try
            {
                dynamic dynManager = _applicationManager;
                var uris = await dynManager.GetPostLogoutRedirectUrisAsync(application);
                if (uris is IEnumerable<string> list)
                {
                    return list.Any(allowed => string.Equals(allowed?.TrimEnd('/'), uri.TrimEnd('/'), StringComparison.OrdinalIgnoreCase));
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Could not retrieve post-logout redirect URIs via manager API; treating as invalid");
                return false;
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Error validating post_logout_redirect_uri");
        }
        return false;
    }
}
