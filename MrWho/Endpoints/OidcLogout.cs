using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using MrWho.Services;
using MrWho.Services.Mediator;
using OpenIddict.Server.AspNetCore;
using Microsoft.AspNetCore; // for extension visibility

namespace MrWho.Endpoints;

public sealed record OidcLogoutRequest(HttpContext HttpContext) : IRequest<IResult>;

public sealed class OidcLogoutHandler : IRequestHandler<OidcLogoutRequest, IResult>
{
    private readonly IDynamicCookieService _dynamicCookieService;
    private readonly ILogger _logger;

    public OidcLogoutHandler(IDynamicCookieService dynamicCookieService, ILogger<OidcLogoutHandler> logger)
    {
        _dynamicCookieService = dynamicCookieService;
        _logger = logger;
    }

    public async Task<IResult> Handle(OidcLogoutRequest request, CancellationToken cancellationToken)
    {
        var context = request.HttpContext;
        var oidcRequest = context.GetOpenIddictServerRequest() ??
                          throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

        try
        {
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
                    _logger.LogInformation("Trying to determine client from post_logout_redirect_uri: {Uri}", postLogoutUri);

                    if (postLogoutUri.Contains("7257") || postLogoutUri.Contains("localhost:7257"))
                    {
                        clientId = "mrwho_admin_web";
                        _logger.LogInformation("Client detected: Admin app (port 7257) {ClientId}", clientId);
                    }
                    else if (postLogoutUri.Contains("7037") || postLogoutUri.Contains("localhost:7037"))
                    {
                        clientId = "mrwho_demo1";
                        _logger.LogInformation("Client detected: Demo1 app (port 7037) {ClientId}", clientId);
                    }
                }
            }

            if (string.IsNullOrEmpty(clientId))
            {
                var referrer = context.Request.Headers.Referer.FirstOrDefault();
                if (!string.IsNullOrEmpty(referrer))
                {
                    _logger.LogInformation("Checking referrer: {Referrer}", referrer);
                    if (referrer.Contains("7257"))
                    {
                        clientId = "mrwho_admin_web";
                    }
                    else if (referrer.Contains("7037"))
                    {
                        clientId = "mrwho_demo1";
                    }
                }
            }

            _logger.LogInformation("Logout request: ClientId={ClientId}, PostLogoutUri={PostLogoutUri}, HasIdToken={HasIdToken}, Referrer={Referrer}",
                clientId ?? "NULL",
                oidcRequest.PostLogoutRedirectUri ?? "NULL",
                !string.IsNullOrEmpty(oidcRequest.IdTokenHint),
                context.Request.Headers.Referer.FirstOrDefault() ?? "NULL");

            if (!string.IsNullOrEmpty(clientId))
            {
                _logger.LogInformation("Client-specific logout for {ClientId}", clientId);
                await _dynamicCookieService.SignOutFromClientAsync(clientId);
            }
            else
            {
                _logger.LogWarning("Fallback logout: no client ID detected. This will affect all clients.");
            }

            return Results.SignOut(authenticationSchemes: new[] { OpenIddictServerAspNetCoreDefaults.AuthenticationScheme });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during client-specific logout for client {ClientId}", oidcRequest.ClientId);
            return Results.SignOut(authenticationSchemes: new[] { OpenIddictServerAspNetCoreDefaults.AuthenticationScheme });
        }
    }
}
