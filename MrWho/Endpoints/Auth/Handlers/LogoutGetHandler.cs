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

        // Try session first, then durable claim on principal
        var externalRegId = http.Session.GetString("ExternalRegistrationId");
        if (string.IsNullOrWhiteSpace(externalRegId))
        {
            externalRegId = http.User?.FindFirst("ext_reg_id")?.Value;
        }
        if (!string.IsNullOrWhiteSpace(externalRegId))
        {
            _logger.LogInformation("External RegistrationId found (session/principal) during GET logout. Initiating external provider sign-out before local logout.");
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

        // Try session first, then durable claim on principal
        var externalRegId = http.Session.GetString("ExternalRegistrationId");
        if (string.IsNullOrWhiteSpace(externalRegId))
        {
            externalRegId = http.User?.FindFirst("ext_reg_id")?.Value;
        }
        if (!string.IsNullOrWhiteSpace(externalRegId))
        {
            _logger.LogInformation("External RegistrationId found (session/principal). Initiating external provider sign-out before local logout.");
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

        // Delegate end-session redirect/sign-out to OpenIddict
        return new SignOutResult(new[] { OpenIddictServerAspNetCoreDefaults.AuthenticationScheme });
    }

    private void DeleteCookieAcrossDomains(HttpContext http, string cookieName)
    {
        http.Response.Cookies.Delete(cookieName, new CookieOptions { Path = "/" });
    }

    private async Task<string?> TryGetClientIdFromRequestAsync(HttpContext http)
    {
        try
        {
            var req = http.GetOpenIddictServerRequest();
            if (!string.IsNullOrEmpty(req?.ClientId)) return req.ClientId;
            var query = http.Request.Query["client_id"].ToString();
            if (!string.IsNullOrEmpty(query)) return query;
        }
        catch { }
        return null;
    }

    private async Task SignOutFromAllSchemesAsync(HttpContext http, string? clientId)
    {
        await _signInManager.SignOutAsync();
        DeleteCookieAcrossDomains(http, ".AspNetCore.Identity.Application");

        if (!string.IsNullOrEmpty(clientId))
        {
            try
            {
                await _dynamicCookieService.SignOutFromClientAsync(clientId);
                var cookieName = _cookieService.GetCookieNameForClient(clientId);
                DeleteCookieAcrossDomains(http, cookieName);
            }
            catch { }
        }
        else
        {
            foreach (var kvp in _cookieService.GetAllClientConfigurations())
            {
                try { await _dynamicCookieService.SignOutFromClientAsync(kvp.Key); } catch { }
                DeleteCookieAcrossDomains(http, kvp.Value.CookieName);
            }
        }
    }
}
