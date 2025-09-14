using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ModelBinding;
using Microsoft.AspNetCore.Mvc.ViewFeatures;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using MrWho.Data;
using MrWho.Options;
using MrWho.Services;
using MrWho.Services.Mediator;
using OpenIddict.Abstractions;

namespace MrWho.Handlers.Auth;

public sealed class LoginGetHandler : IRequestHandler<MrWho.Endpoints.Auth.LoginGetRequest, IActionResult>
{
    private readonly IClientCookieConfigurationService _cookieService;
    private readonly IDynamicCookieService _dynamicCookieService;
    private readonly IOpenIddictApplicationManager _applicationManager;
    private readonly ApplicationDbContext _db;
    private readonly ILogger<LoginGetHandler> _logger;
    private readonly ILoginHelper _loginHelper;
    private readonly IOptions<MrWhoOptions> _mrWhoOptions;

    public LoginGetHandler(
        IClientCookieConfigurationService cookieService,
        IDynamicCookieService dynamicCookieService,
        IOpenIddictApplicationManager applicationManager,
        ApplicationDbContext db,
        ILogger<LoginGetHandler> logger,
        ILoginHelper loginHelper,
        IOptions<MrWhoOptions> mrWhoOptions)
    {
        _cookieService = cookieService;
        _dynamicCookieService = dynamicCookieService;
        _applicationManager = applicationManager;
        _db = db;
        _logger = logger;
        _loginHelper = loginHelper;
        _mrWhoOptions = mrWhoOptions;
    }

    public async Task<IActionResult> Handle(MrWho.Endpoints.Auth.LoginGetRequest request, CancellationToken cancellationToken)
    {
        var http = request.HttpContext;
        var returnUrl = request.ReturnUrl;
        var clientId = request.ClientId;
        var mode = request.Mode;

        _logger.LogDebug("Login page requested, returnUrl = {ReturnUrl}, clientId = {ClientId}", returnUrl, clientId);

        if (string.IsNullOrEmpty(clientId) && !string.IsNullOrEmpty(returnUrl))
        {
            var extracted = _loginHelper.TryExtractClientIdFromReturnUrl(returnUrl);
            if (!string.IsNullOrEmpty(extracted))
            {
                clientId = extracted;
                _logger.LogDebug("Extracted client_id '{ClientId}' from returnUrl", clientId);
            }
        }

        var viewData = NewViewData();
        viewData["ReturnUrl"] = returnUrl;
        viewData["ClientId"] = clientId;
        viewData["RecaptchaSiteKey"] = _loginHelper.GetRecaptchaSiteKey();

        string? clientName = null;
        bool allowLocal = true, allowPasskey = true, allowQrQuick = true, allowQrSecure = true, allowCode = true;
        if (!string.IsNullOrEmpty(clientId))
        {
            try
            {
                var application = await _applicationManager.FindByClientIdAsync(clientId);
                if (application != null)
                {
                    clientName = await _applicationManager.GetDisplayNameAsync(application);
                    if (string.IsNullOrEmpty(clientName)) clientName = clientId;
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to retrieve client information for clientId: {ClientId}", clientId);
            }
        }
        viewData["ClientName"] = clientName;

        try
        {
            // Load client and compute dynamic branding (logo/theme) + external providers
            var client = await _db.Clients
                .AsNoTracking()
                .Include(c => c.Realm)
                .FirstOrDefaultAsync(c => c.ClientId == clientId, cancellationToken);

            // Visible login options
            if (client != null)
            {
                allowLocal = client.EnableLocalLogin ?? true;
                allowPasskey = client.AllowPasskeyLogin ?? true;
                allowQrQuick = client.AllowQrLoginQuick ?? true;
                allowQrSecure = client.AllowQrLoginSecure ?? true;
                allowCode = client.AllowCodeLogin ?? true;
            }
            viewData["AllowLocalLogin"] = allowLocal;
            viewData["AllowPasskeyLogin"] = allowPasskey;
            viewData["AllowQrLoginQuick"] = allowQrQuick;
            viewData["AllowQrLoginSecure"] = allowQrSecure;
            viewData["AllowCodeLogin"] = allowCode;

            // Compute theme and custom CSS with precedence: client > realm > server
            string? themeName = null;
            string? customCssUrl = null;
            if (client != null)
            {
                themeName = client.ThemeName ?? client.Realm?.DefaultThemeName ?? _mrWhoOptions.Value.DefaultThemeName;
                customCssUrl = client.CustomCssUrl ?? client.Realm?.RealmCustomCssUrl;
            }
            else
            {
                themeName = _mrWhoOptions.Value.DefaultThemeName;
            }
            if (!string.IsNullOrWhiteSpace(themeName))
            {
                viewData["ThemeName"] = themeName;
            }
            if (!string.IsNullOrWhiteSpace(customCssUrl))
            {
                viewData["CustomCssUrl"] = customCssUrl;
            }

            // Compute logo URI if available (client-level preferred, realm-level fallback)
            if (client != null)
            {
                string? logoUri = null;

                try
                {
                    // Prefer explicit client logo when allowed
                    var showClientLogo = (bool?)client.GetType().GetProperty("ShowClientLogo")?.GetValue(client) ?? true; // default to true when missing
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
                    _logger.LogDebug(ex, "Failed to compute client/realm logo for client {ClientId}", clientId);
                }

                viewData["LogoUri"] = logoUri; // may be null -> view will fallback to default logo

                // External providers filtered by client assignment
                var query = _db.IdentityProviders.Include(p => p.ClientLinks)
                    .AsSplitQuery()
                    .AsNoTracking()
                    .Where(p => p.IsEnabled && p.Type == MrWho.Shared.IdentityProviderType.Oidc);

                var providers = await query
                    .OrderBy(p => p.Order)
                    .ThenBy(p => p.Name)
                    .Select(p => new { p.Name, DisplayName = p.DisplayName ?? p.Name, p.IconUri, p.ClientLinks })
                    .ToListAsync(cancellationToken);

                if (!string.IsNullOrEmpty(clientId))
                {
                    providers = providers.Where(p => p.ClientLinks.Any(cl => cl.ClientId == client?.Id)).ToList();
                }
                viewData["ExternalProviders"] = providers;
            }
            else
            {
                _logger.LogWarning("No client found for clientId: {ClientId}", clientId);
                viewData["ExternalProviders"] = Array.Empty<object>();
                viewData["LogoUri"] = null; // ensure not set
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to load external identity providers for login page");
            viewData["ExternalProviders"] = Array.Empty<object>();
            viewData["LogoUri"] = null;
        }

        var useCode = string.Equals(mode, "code", StringComparison.OrdinalIgnoreCase);
        // If code mode is not allowed, force to password
        if (!allowCode) useCode = false;
        var model = new MrWho.Controllers.LoginViewModel { UseCode = useCode };
        return new ViewResult
        {
            ViewName = "Login",
            ViewData = viewDataWithModel(viewData, model)
        };
    }

    private static ViewDataDictionary NewViewData() => new(new EmptyModelMetadataProvider(), new ModelStateDictionary());
    private static ViewDataDictionary viewDataWithModel(ViewDataDictionary vd, object model) { vd.Model = model; return vd; }
}
