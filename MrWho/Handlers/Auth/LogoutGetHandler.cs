using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.AspNetCore.Http.Features; // added for session feature check
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ModelBinding;
using Microsoft.AspNetCore.Mvc.ViewFeatures;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Options;
using MrWho.Data;
using MrWho.Options;
using MrWho.Services;
using MrWho.Services.Mediator;
using MrWho.Shared.Constants; // added
using OpenIddict.Abstractions;
using OpenIddict.Client.AspNetCore;
using OpenIddict.Server.AspNetCore;

namespace MrWho.Handlers.Auth;

public sealed class LogoutGetHandler : IRequestHandler<MrWho.Endpoints.Auth.LogoutGetRequest, IActionResult>
{
    private readonly ILogger<LogoutGetHandler> _logger;
    private readonly ILogoutHelper _logoutHelper;
    private readonly ApplicationDbContext _db;
    private readonly IOptions<MrWhoOptions> _mrWhoOptions;

    public LogoutGetHandler(
        ILogger<LogoutGetHandler> logger,
        ILogoutHelper logoutHelper,
        ApplicationDbContext db,
        IOptions<MrWhoOptions> mrWhoOptions)
    {
        _logger = logger;
        _logoutHelper = logoutHelper;
        _db = db;
        _mrWhoOptions = mrWhoOptions;
    }

    public async Task<IActionResult> Handle(MrWho.Endpoints.Auth.LogoutGetRequest request, CancellationToken cancellationToken)
    {
        var http = request.HttpContext;
        static bool HasSession(HttpContext ctx) => ctx.Features.Get<ISessionFeature>()?.Session != null;
        string? SafeSessionGet(HttpContext ctx, string key)
        {
            if (!HasSession(ctx))
            {
                return null;
            }

            try { return ctx.Session.GetString(key); } catch { return null; }
        }
        void SafeSessionSet(HttpContext ctx, string key, string value)
        {
            if (!HasSession(ctx))
            {
                return;
            }

            try { ctx.Session.SetString(key, value); } catch { }
        }

        var clientId = request.ClientId;
        var postUri = request.PostLogoutRedirectUri;

        var audit = http.RequestServices.GetService<ISecurityAuditWriter>();
        var sid = http.User?.FindFirst("sid")?.Value; // capture before sign-out
        var issuer = (http.Request.Scheme + "://" + http.Request.Host).TrimEnd('/');
        try { if (audit != null) { await audit.WriteAsync("logout", "logout.initiated", new { clientId, postUri, sid }, "info", actorClientId: clientId, ip: http.Connection.RemoteIpAddress?.ToString()); } } catch { }

        _logger.LogInformation("GET /connect/logout accessed directly. ClientId: {ClientId}, PostLogoutUri: {PostLogoutUri}", clientId, postUri);
        bool isOidcLogoutRequest = _logoutHelper.IsOidcLogoutRequest(http);
        if (isOidcLogoutRequest)
        {
            return await ProcessLogoutInternalAsync(http, clientId, postUri, cancellationToken);
        }

        var externalRegId = SafeSessionGet(http, "ExternalRegistrationId");
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
            SafeSessionSet(http, "ExternalSignoutResumeUrl", returnAfterExternal ?? "/");

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

        var vd = new ViewDataDictionary(new EmptyModelMetadataProvider(), new ModelStateDictionary())
        {
            [ViewDataKeys.ClientId] = clientId,
            [ViewDataKeys.ReturnUrl] = postUri
        };
        try
        {
            string? themeName = null;
            string? customCssUrl = null;
            string? logoUri = null;
            string? clientName = null;

            if (!string.IsNullOrEmpty(clientId))
            {
                var client = await _db.Clients.AsNoTracking().Include(c => c.Realm).FirstOrDefaultAsync(c => c.ClientId == clientId, cancellationToken);
                if (client != null)
                {
                    clientName = client.Name ?? client.ClientId;
                    themeName = client.ThemeName ?? client.Realm?.DefaultThemeName ?? _mrWhoOptions.Value.DefaultThemeName;
                    customCssUrl = client.CustomCssUrl ?? client.Realm?.RealmCustomCssUrl;
                    var showClientLogo = (bool?)client.GetType().GetProperty("ShowClientLogo")?.GetValue(client) ?? true;
                    var clientLogo = (string?)client.GetType().GetProperty("LogoUri")?.GetValue(client);
                    if (showClientLogo && !string.IsNullOrWhiteSpace(clientLogo))
                    {
                        logoUri = clientLogo;
                    }
                    else if (!string.IsNullOrWhiteSpace(client.Realm?.RealmLogoUri))
                    {
                        logoUri = client.Realm!.RealmLogoUri;
                    }
                }
            }
            else
            {
                themeName = _mrWhoOptions.Value.DefaultThemeName;
            }

            if (!string.IsNullOrWhiteSpace(themeName))
            {
                vd[ViewDataKeys.ThemeName] = themeName;
            }

            if (!string.IsNullOrWhiteSpace(customCssUrl))
            {
                vd[ViewDataKeys.CustomCssUrl] = customCssUrl;
            }

            if (!string.IsNullOrWhiteSpace(logoUri))
            {
                vd[ViewDataKeys.LogoUri] = logoUri;
            }

            if (!string.IsNullOrWhiteSpace(clientName))
            {
                vd[ViewDataKeys.ClientName] = clientName;
            }
        }
        catch { }

        try
        {
            if (!string.IsNullOrEmpty(sid))
            {
                var iframeUrls = await _db.Clients.AsNoTracking()
                    .Where(c => c.IsEnabled && c.FrontChannelLogoutUri != null && c.FrontChannelLogoutUri != "")
                    .Select(c => new { c.ClientId, c.FrontChannelLogoutUri })
                    .ToListAsync(cancellationToken);
                var list = new List<string>();
                foreach (var c in iframeUrls)
                {
                    try
                    {
                        var sep = c.FrontChannelLogoutUri!.Contains('?') ? '&' : '?';
                        var url = $"{c.FrontChannelLogoutUri}{sep}iss={Uri.EscapeDataString(issuer)}&sid={Uri.EscapeDataString(sid)}&client_id={Uri.EscapeDataString(c.ClientId)}";
                        list.Add(url);
                        try { if (audit != null) { await audit.WriteAsync("logout", "logout.frontchannel.dispatch", new { c.ClientId, url }, "info", actorClientId: c.ClientId, ip: http.Connection.RemoteIpAddress?.ToString()); } } catch { }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogDebug(ex, "Failed to build front-channel logout iframe for client {ClientId}", c.ClientId);
                    }
                }
                if (list.Count > 0)
                {
                    http.Items["FrontChannelLogoutIframes"] = list;
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Error enumerating front-channel logout iframes");
        }

        return new ViewResult { ViewName = "LoggedOut", ViewData = vd };
    }

    private async Task<IActionResult> ProcessLogoutInternalAsync(HttpContext http, string? clientId, string? postLogoutUri, CancellationToken ct)
    {
        static bool HasSession(HttpContext ctx) => ctx.Features.Get<ISessionFeature>()?.Session != null;
        void SafeSessionSet(HttpContext ctx, string key, string value) { if (!HasSession(ctx)) { return; } try { ctx.Session.SetString(key, value); } catch { } }
        var request = http.GetOpenIddictServerRequest();
        string? detectedClientId = clientId ?? await _logoutHelper.TryGetClientIdFromRequestAsync(http);
        var audit = http.RequestServices.GetService<ISecurityAuditWriter>();
        var sid = http.User?.FindFirst("sid")?.Value; // capture before sign-out
        var issuer = (http.Request.Scheme + "://" + http.Request.Host).TrimEnd('/');
        try { if (audit != null) { await audit.WriteAsync("logout", "logout.initiated", new { clientId = detectedClientId, postLogoutUri, sid, oidc = true }, "info", actorClientId: detectedClientId, ip: http.Connection.RemoteIpAddress?.ToString()); } } catch { }

        _logger.LogDebug("Processing OIDC logout. Method: {Method}, ClientId parameter: {ClientId}, Detected ClientId: {DetectedClientId}, Post logout URI: {PostLogoutUri}", http.Request.Method, clientId, detectedClientId, postLogoutUri ?? request?.PostLogoutRedirectUri);

        if (_logoutHelper.UseGlobalLogout(http))
        {
            await _logoutHelper.SignOutGlobalAsync(http, detectedClientId);
        }
        else
        {
            await _logoutHelper.SignOutClientOnlyAsync(http, detectedClientId);
        }

        try
        {
            if (!string.IsNullOrEmpty(sid))
            {
                var iframes = await _db.Clients.AsNoTracking()
                    .Where(c => c.IsEnabled && c.FrontChannelLogoutUri != null && c.FrontChannelLogoutUri != "")
                    .Select(c => new { c.ClientId, c.FrontChannelLogoutUri })
                    .ToListAsync(ct);
                var list = new List<string>();
                foreach (var c in iframes)
                {
                    try
                    {
                        var sep = c.FrontChannelLogoutUri!.Contains('?') ? '&' : '?';
                        var url = $"{c.FrontChannelLogoutUri}{sep}iss={Uri.EscapeDataString(issuer)}&sid={Uri.EscapeDataString(sid)}&client_id={Uri.EscapeDataString(c.ClientId)}";
                        list.Add(url);
                        try { if (audit != null) { await audit.WriteAsync("logout", "logout.frontchannel.dispatch", new { c.ClientId, url, oidc = true }, "info", actorClientId: c.ClientId, ip: http.Connection.RemoteIpAddress?.ToString()); } } catch { }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogDebug(ex, "Failed to build OIDC front-channel logout iframe for client {ClientId}", c.ClientId);
                    }
                }
                if (list.Count > 0)
                {
                    http.Items["FrontChannelLogoutIframes"] = list;
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Error enumerating OIDC front-channel logout iframes");
        }

        _logoutHelper.DeleteCookieAcrossDomains(http, ".AspNetCore.Identity.Application");
        return new SignOutResult(new[] { OpenIddictServerAspNetCoreDefaults.AuthenticationScheme });
    }
}
