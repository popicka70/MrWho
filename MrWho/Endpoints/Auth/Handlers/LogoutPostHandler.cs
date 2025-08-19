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

    public LogoutPostHandler(ILogger<LogoutPostHandler> logger, SignInManager<IdentityUser> signInManager, IClientCookieConfigurationService cookieService, IDynamicCookieService dynamicCookieService)
    {
        _logger = logger;
        _signInManager = signInManager;
        _cookieService = cookieService;
        _dynamicCookieService = dynamicCookieService;
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
            return new SignOutResult(new[] { OpenIddictServerAspNetCoreDefaults.AuthenticationScheme });
        }

        // Try session first, then durable claim on principal
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

        await _signInManager.SignOutAsync();
        http.Response.Cookies.Delete(".AspNetCore.Identity.Application", new CookieOptions { Path = "/" });

        string? detectedClientId = clientId;
        if (!string.IsNullOrEmpty(detectedClientId))
        {
            try
            {
                await _dynamicCookieService.SignOutFromClientAsync(detectedClientId);
                var cookieName = _cookieService.GetCookieNameForClient(detectedClientId);
                http.Response.Cookies.Delete(cookieName, new CookieOptions { Path = "/" });
            }
            catch (Exception ex) { _logger.LogWarning(ex, "Failed to sign out from client-specific cookie for client {ClientId}", detectedClientId); }
        }
        else
        {
            foreach (var kvp in _cookieService.GetAllClientConfigurations())
            {
                try { await _dynamicCookieService.SignOutFromClientAsync(kvp.Key); } catch { }
                http.Response.Cookies.Delete(kvp.Value.CookieName, new CookieOptions { Path = "/" });
            }
        }

        return new RedirectToActionResult("Index", "Home", new { logout = "success" });
    }
}
