using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ModelBinding;
using Microsoft.AspNetCore.Mvc.ViewFeatures;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using MrWho.Data;
using MrWho.Services;
using MrWho.Services.Mediator;
using OpenIddict.Abstractions;
using Microsoft.Extensions.Options;
using MrWho.Options;

namespace MrWho.Endpoints.Auth;

public sealed class LoginGetHandler : IRequestHandler<LoginGetRequest, IActionResult>
{
    private readonly SignInManager<IdentityUser> _signInManager;
    private readonly UserManager<IdentityUser> _userManager;
    private readonly IClientCookieConfigurationService _cookieService;
    private readonly IDynamicCookieService _dynamicCookieService;
    private readonly IOpenIddictApplicationManager _applicationManager;
    private readonly ApplicationDbContext _db;
    private readonly ILogger<LoginGetHandler> _logger;
    private readonly IConfiguration _configuration;
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly IHostEnvironment _env;
    private readonly IOptions<MrWhoOptions> _mrWhoOptions;

    public LoginGetHandler(
        SignInManager<IdentityUser> signInManager,
        UserManager<IdentityUser> userManager,
        IClientCookieConfigurationService cookieService,
        IDynamicCookieService dynamicCookieService,
        IOpenIddictApplicationManager applicationManager,
        ApplicationDbContext db,
        ILogger<LoginGetHandler> logger,
        IConfiguration configuration,
        IHttpClientFactory httpClientFactory,
        IHostEnvironment env,
        IOptions<MrWhoOptions> mrWhoOptions)
    {
        _signInManager = signInManager;
        _userManager = userManager;
        _cookieService = cookieService;
        _dynamicCookieService = dynamicCookieService;
        _applicationManager = applicationManager;
        _db = db;
        _logger = logger;
        _configuration = configuration;
        _httpClientFactory = httpClientFactory;
        _env = env;
        _mrWhoOptions = mrWhoOptions;
    }

    public async Task<IActionResult> Handle(LoginGetRequest request, CancellationToken cancellationToken)
    {
        var http = request.HttpContext;
        var returnUrl = request.ReturnUrl;
        var clientId = request.ClientId;
        var mode = request.Mode;

        _logger.LogDebug("Login page requested, returnUrl = {ReturnUrl}, clientId = {ClientId}", returnUrl, clientId);

        if (string.IsNullOrEmpty(clientId) && !string.IsNullOrEmpty(returnUrl))
        {
            var extracted = TryExtractClientIdFromReturnUrl(returnUrl);
            if (!string.IsNullOrEmpty(extracted))
            {
                clientId = extracted;
                _logger.LogDebug("Extracted client_id '{ClientId}' from returnUrl", clientId);
            }
        }

        var viewData = NewViewData();
        viewData["ReturnUrl"] = returnUrl;
        viewData["ClientId"] = clientId;
        viewData["RecaptchaSiteKey"] = ShouldUseRecaptcha() ? _configuration["GoogleReCaptcha:SiteKey"] : null;

        string? clientName = null;
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
        var model = new MrWho.Controllers.LoginViewModel { UseCode = useCode };
        return new ViewResult
        {
            ViewName = "Login",
            ViewData = viewDataWithModel(viewData, model)
        };
    }

    private bool ShouldUseRecaptcha()
    {
        if (_env.IsDevelopment()) return false;
        var site = _configuration["GoogleReCaptcha:SiteKey"];
        var secret = _configuration["GoogleReCaptcha:SecretKey"];
        var enabledFlag = _configuration["GoogleReCaptcha:Enabled"];
        if (!string.IsNullOrWhiteSpace(enabledFlag) && bool.TryParse(enabledFlag, out var enabled) && !enabled)
            return false;
        return !string.IsNullOrWhiteSpace(site) && !string.IsNullOrWhiteSpace(secret);
    }

    private static string? TryExtractClientIdFromReturnUrl(string? returnUrl)
    {
        if (string.IsNullOrEmpty(returnUrl)) return null;
        try
        {
            if (Uri.TryCreate(returnUrl, UriKind.Absolute, out var absUri))
            {
                var query = System.Web.HttpUtility.ParseQueryString(absUri.Query);
                return query["client_id"];            
            }
            else
            {
                var idx = returnUrl.IndexOf('?');
                if (idx >= 0 && idx < returnUrl.Length - 1)
                {
                    var query = System.Web.HttpUtility.ParseQueryString(returnUrl.Substring(idx));
                    return query["client_id"];            
                }
            }
        }
        catch { }
        return null;
    }

    private static ViewDataDictionary NewViewData() => new(new EmptyModelMetadataProvider(), new ModelStateDictionary());
    private static ViewDataDictionary viewDataWithModel(ViewDataDictionary vd, object model) { vd.Model = model; return vd; }
}
