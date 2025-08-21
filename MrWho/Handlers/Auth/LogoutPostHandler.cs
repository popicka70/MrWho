using Microsoft.AspNetCore; // for OpenIddict HttpContext extensions
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using MrWho.Services;
using MrWho.Services.Mediator;
using OpenIddict.Client.AspNetCore;
using OpenIddict.Server.AspNetCore;

namespace MrWho.Handlers.Auth;

public sealed class LogoutPostHandler : IRequestHandler<MrWho.Endpoints.Auth.LogoutPostRequest, IActionResult>
{
    private readonly ILogger<LogoutPostHandler> _logger;
    private readonly ILogoutHelper _logoutHelper;

    public LogoutPostHandler(ILogger<LogoutPostHandler> logger, ILogoutHelper logoutHelper)
    {
        _logger = logger;
        _logoutHelper = logoutHelper;
    }

    public async Task<IActionResult> Handle(MrWho.Endpoints.Auth.LogoutPostRequest request, CancellationToken cancellationToken)
    {
        var http = request.HttpContext;
        var clientId = request.ClientId;
        var postUri = request.PostLogoutRedirectUri;

        _logger.LogInformation("POST /connect/logout accessed. ClientId: {ClientId}, PostLogoutUri: {PostLogoutUri}", clientId, postUri);
        bool isOidcLogoutRequest = _logoutHelper.IsOidcLogoutRequest(http);
        if (isOidcLogoutRequest)
        {
            if (_logoutHelper.UseGlobalLogout(http))
            {
                await _logoutHelper.SignOutGlobalAsync(http, clientId);
            }
            else
            {
                await _logoutHelper.SignOutClientOnlyAsync(http, clientId);
            }
            // Clear the default Identity cookie
            _logoutHelper.DeleteCookieAcrossDomains(http, ".AspNetCore.Identity.Application");
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
}
