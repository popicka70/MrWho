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

namespace MrWho.Handlers.Auth;

public sealed class LogoutGetHandler : IRequestHandler<MrWho.Endpoints.Auth.LogoutGetRequest, IActionResult>
{
    private readonly ILogger<LogoutGetHandler> _logger;
    private readonly ILogoutHelper _logoutHelper;

    public LogoutGetHandler(
        ILogger<LogoutGetHandler> logger,
        ILogoutHelper logoutHelper)
    {
        _logger = logger;
        _logoutHelper = logoutHelper;
    }

    public async Task<IActionResult> Handle(MrWho.Endpoints.Auth.LogoutGetRequest request, CancellationToken cancellationToken)
    {
        var http = request.HttpContext;
        var clientId = request.ClientId;
        var postUri = request.PostLogoutRedirectUri;

        _logger.LogInformation("GET /connect/logout accessed directly. ClientId: {ClientId}, PostLogoutUri: {PostLogoutUri}", clientId, postUri);
        bool isOidcLogoutRequest = _logoutHelper.IsOidcLogoutRequest(http);
        if (isOidcLogoutRequest)
        {
            return await ProcessLogoutInternalAsync(http, clientId, postUri, cancellationToken);
        }

        // Try session first, then durable claim on principal for direct (non-OIDC) logout
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

        if (_logoutHelper.UseGlobalLogout(http))
        {
            await _logoutHelper.SignOutGlobalAsync(http, clientId);
        }
        else
        {
            await _logoutHelper.SignOutClientOnlyAsync(http, clientId);
        }

        return new RedirectToActionResult("Index", "Home", new { logout = "success" });
    }

    private async Task<IActionResult> ProcessLogoutInternalAsync(HttpContext http, string? clientId, string? postLogoutUri, CancellationToken ct)
    {
        var request = http.GetOpenIddictServerRequest();
        string? detectedClientId = clientId ?? await _logoutHelper.TryGetClientIdFromRequestAsync(http);
        _logger.LogDebug("Processing OIDC logout. Method: {Method}, ClientId parameter: {ClientId}, Detected ClientId: {DetectedClientId}, Post logout URI: {PostLogoutUri}", http.Request.Method, clientId, detectedClientId, postLogoutUri ?? request?.PostLogoutRedirectUri);

        if (_logoutHelper.UseGlobalLogout(http))
        {
            await _logoutHelper.SignOutGlobalAsync(http, detectedClientId);
        }
        else
        {
            // IMPORTANT: For OIDC logout, only sign the initiating client out locally to avoid impacting other clients.
            await _logoutHelper.SignOutClientOnlyAsync(http, detectedClientId);
        }

        // Delegate end-session redirect/sign-out to OpenIddict
        // Clear the default Identity cookie
        _logoutHelper.DeleteCookieAcrossDomains(http, ".AspNetCore.Identity.Application");
        return new SignOutResult(new[] { OpenIddictServerAspNetCoreDefaults.AuthenticationScheme });
    }
}
