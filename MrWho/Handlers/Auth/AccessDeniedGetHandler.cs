using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ModelBinding;
using Microsoft.AspNetCore.Mvc.ViewFeatures;
using Microsoft.EntityFrameworkCore; // added
using Microsoft.Extensions.Options; // added
using MrWho.Data; // added
using MrWho.Options; // added
using MrWho.Services.Mediator;
using OpenIddict.Abstractions;

namespace MrWho.Handlers.Auth;

public sealed class AccessDeniedGetHandler : IRequestHandler<MrWho.Endpoints.Auth.AccessDeniedGetRequest, IActionResult>
{
    private readonly IOpenIddictApplicationManager _applicationManager;
    private readonly ILogger<AccessDeniedGetHandler> _logger;
    private readonly ApplicationDbContext _db; // added
    private readonly IOptions<MrWhoOptions> _mrWhoOptions; // added

    public AccessDeniedGetHandler(
        IOpenIddictApplicationManager applicationManager,
        ILogger<AccessDeniedGetHandler> logger,
        ApplicationDbContext db,
        IOptions<MrWhoOptions> mrWhoOptions)
    {
        _applicationManager = applicationManager;
        _logger = logger;
        _db = db;
        _mrWhoOptions = mrWhoOptions;
    }

    public async Task<IActionResult> Handle(MrWho.Endpoints.Auth.AccessDeniedGetRequest request, CancellationToken cancellationToken)
    {
        var returnUrl = request.ReturnUrl;
        var clientId = request.ClientId;
        _logger.LogDebug("Access denied page requested, returnUrl = {ReturnUrl}, clientId = {ClientId}", returnUrl, clientId);
        var vd = new ViewDataDictionary(new EmptyModelMetadataProvider(), new ModelStateDictionary())
        {
            ["ReturnUrl"] = returnUrl,
            ["ClientId"] = clientId
        };

        if (string.IsNullOrEmpty(clientId) && !string.IsNullOrEmpty(returnUrl))
        {
            try
            {
                if (Uri.TryCreate(returnUrl, UriKind.Absolute, out var absUri))
                {
                    var query = System.Web.HttpUtility.ParseQueryString(absUri.Query);
                    clientId = query["client_id"];
                }
                else if (Uri.TryCreate(returnUrl, UriKind.Relative, out var _))
                {
                    var idx = returnUrl.IndexOf('?');
                    if (idx >= 0 && idx < returnUrl.Length - 1)
                    {
                        var query = System.Web.HttpUtility.ParseQueryString(returnUrl.Substring(idx));
                        clientId = query["client_id"];
                    }
                }
                vd["ClientId"] = clientId;
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Failed to extract client_id from returnUrl: {ReturnUrl}", returnUrl);
            }
        }

        string? clientName = null;
        if (!string.IsNullOrEmpty(clientId))
        {
            try
            {
                var application = await _applicationManager.FindByClientIdAsync(clientId);
                if (application != null)
                {
                    clientName = await _applicationManager.GetDisplayNameAsync(application) ?? clientId;
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to retrieve client information for clientId: {ClientId}", clientId);
            }
        }

        // Compute theme, custom CSS and logo like on Login page
        try
        {
            string? themeName = null;
            string? customCssUrl = null;
            string? logoUri = null;

            if (!string.IsNullOrEmpty(clientId))
            {
                var client = await _db.Clients
                    .AsNoTracking()
                    .Include(c => c.Realm)
                    .FirstOrDefaultAsync(c => c.ClientId == clientId, cancellationToken);

                if (client != null)
                {
                    themeName = client.ThemeName ?? client.Realm?.DefaultThemeName ?? _mrWhoOptions.Value.DefaultThemeName;
                    customCssUrl = client.CustomCssUrl ?? client.Realm?.RealmCustomCssUrl;

                    try
                    {
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
                    catch (Exception ex)
                    {
                        _logger.LogDebug(ex, "Failed computing logo for client {ClientId}", clientId);
                    }
                }
                else
                {
                    themeName = _mrWhoOptions.Value.DefaultThemeName;
                }
            }
            else
            {
                themeName = _mrWhoOptions.Value.DefaultThemeName;
            }

            if (!string.IsNullOrWhiteSpace(themeName))
                vd["ThemeName"] = themeName;
            if (!string.IsNullOrWhiteSpace(customCssUrl))
                vd["CustomCssUrl"] = customCssUrl;
            if (!string.IsNullOrWhiteSpace(logoUri))
                vd["LogoUri"] = logoUri;
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Failed to compute theme/custom assets for AccessDenied");
        }

        vd["ClientName"] = clientName;
        return new ViewResult { ViewName = "AccessDenied", ViewData = vd };
    }
}
