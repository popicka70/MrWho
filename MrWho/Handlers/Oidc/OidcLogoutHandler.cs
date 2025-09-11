using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using MrWho.Services;
using MrWho.Services.Mediator;
using OpenIddict.Server.AspNetCore;
using Microsoft.AspNetCore; // for extension visibility
using Microsoft.AspNetCore.Authentication;
using OpenIddict.Client.AspNetCore;

namespace MrWho.Handlers.Oidc;

public sealed class OidcLogoutHandler : IRequestHandler<MrWho.Endpoints.OidcLogoutRequest, IResult>
{
    private readonly IDynamicCookieService _dynamicCookieService;
    private readonly ILogger<OidcLogoutHandler> _logger;

    public OidcLogoutHandler(IDynamicCookieService dynamicCookieService, ILogger<OidcLogoutHandler> logger)
    {
        _dynamicCookieService = dynamicCookieService;
        _logger = logger;
    }

    public async Task<IResult> Handle(MrWho.Endpoints.OidcLogoutRequest request, CancellationToken cancellationToken)
    {
        var context = request.HttpContext;
        var oidcRequest = context.GetOpenIddictServerRequest();
        if (oidcRequest is null)
        {
            throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");
        }
        var audit = context.RequestServices.GetService<ISecurityAuditWriter>();

        try
        {
            // If this OP session was established via an external IdP, cascade sign-out first
            var externalRegId = context.Session.GetString("ExternalRegistrationId");
            if (!string.IsNullOrWhiteSpace(externalRegId))
            {
                // Save a resume URL so that when external sign-out finishes, we re-enter this endpoint
                var resume = context.Request.Path + context.Request.QueryString.Value;
                context.Session.SetString("ExternalSignoutResumeUrl", resume);

                _logger.LogInformation("Cascading logout: initiating external sign-out for registration {RegistrationId} before OP end-session", externalRegId);
                var props = new AuthenticationProperties
                {
                    RedirectUri = "/connect/external/signout-callback"
                };
                props.Items[OpenIddictClientAspNetCoreConstants.Properties.RegistrationId] = externalRegId;

                await context.SignOutAsync(OpenIddictClientAspNetCoreDefaults.AuthenticationScheme, props);

                // Short-circuit: the response is a redirect to the external end-session
                return Results.Empty;
            }

            var clientId = oidcRequest.ClientId ??
                           context.Items["ClientId"]?.ToString() ??
                           context.Request.Query["client_id"].FirstOrDefault() ??
                           context.Request.Form["client_id"].FirstOrDefault();

            if (string.IsNullOrEmpty(clientId))
            {
                var postLogoutUri = oidcRequest.PostLogoutRedirectUri ??
                                     context.Request.Query["post_logout_redirect_uri"].FirstOrDefault() ??
                                     context.Request.Form["post_logout_redirect_uri"].FirstOrDefault();

                if (!string.IsNullOrEmpty(postLogoutUri))
                {
                    _logger.LogInformation("OIDC logout without client_id. Skipping client cookie cleanup and delegating to OP.");
                    return Results.SignOut(authenticationSchemes: new[] { OpenIddictServerAspNetCoreDefaults.AuthenticationScheme });
                }

                _logger.LogWarning("End session request missing client_id and post_logout_redirect_uri; delegating to OP");
                return Results.SignOut(authenticationSchemes: new[] { OpenIddictServerAspNetCoreDefaults.AuthenticationScheme });
            }

            await _dynamicCookieService.SignOutFromClientAsync(clientId);
            if (audit != null) await audit.WriteAsync("auth.security", "logout.client", new { clientId }, "info", actorClientId: clientId, ip: context.Connection.RemoteIpAddress?.ToString());
            return Results.SignOut(authenticationSchemes: new[] { OpenIddictServerAspNetCoreDefaults.AuthenticationScheme });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error processing OIDC logout");
            if (audit != null) await audit.WriteAsync("auth.security", "logout.error", new { ex = ex.Message }, "error", ip: context.Connection.RemoteIpAddress?.ToString());
            return Results.Problem("Error processing logout");
        }
    }
}
