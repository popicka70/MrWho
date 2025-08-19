using System.Security.Claims;
using Microsoft.AspNetCore; // added for OpenIddict HttpContext extensions
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ModelBinding;
using Microsoft.AspNetCore.Mvc.ViewFeatures;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.AspNetCore.Http; // added
using Microsoft.AspNetCore.Http.Extensions; // added
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore; // added for HttpContext extensions
using MrWho.Data;
using MrWho.Models;
using MrWho.Services;
using MrWho.Services.Mediator;
using MrWho.Shared.Models;
using System.Text.Json;
using MrWho.Controllers; // for LoginViewModel

namespace MrWho.Endpoints.Auth;

// Requests
public sealed record LoginGetRequest(HttpContext HttpContext, string? ReturnUrl, string? ClientId, string? Mode) : IRequest<IActionResult>;
public sealed record LoginPostRequest(HttpContext HttpContext, MrWho.Controllers.LoginViewModel Model, string? ReturnUrl, string? ClientId) : IRequest<IActionResult>;
public sealed record LogoutGetRequest(HttpContext HttpContext, string? ClientId, string? PostLogoutRedirectUri) : IRequest<IActionResult>;
public sealed record LogoutPostRequest(HttpContext HttpContext, string? ClientId, string? PostLogoutRedirectUri) : IRequest<IActionResult>;
public sealed record ProcessLogoutRequest(HttpContext HttpContext, string? ClientId, string? PostLogoutRedirectUri) : IRequest<IActionResult>;
public sealed record AccessDeniedGetRequest(HttpContext HttpContext, string? ReturnUrl, string? ClientId) : IRequest<IActionResult>;
public sealed record RegisterGetRequest(HttpContext HttpContext) : IRequest<IActionResult>;
public sealed record RegisterPostRequest(HttpContext HttpContext, RegisterUserRequest Input) : IRequest<IActionResult>;
public sealed record RegisterSuccessGetRequest() : IRequest<IActionResult>;

// Handlers
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
        IHostEnvironment env)
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
            var client = await _db.Clients.AsNoTracking().FirstOrDefaultAsync(c => c.ClientId == clientId, cancellationToken);
            if (client != null)
            {
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
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to load external identity providers for login page");
            viewData["ExternalProviders"] = Array.Empty<object>();
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

public sealed class LoginPostHandler : IRequestHandler<LoginPostRequest, IActionResult>
{
    private readonly SignInManager<IdentityUser> _signInManager;
    private readonly UserManager<IdentityUser> _userManager;
    private readonly IClientCookieConfigurationService _cookieService;
    private readonly IDynamicCookieService _dynamicCookieService;
    private readonly IOpenIddictApplicationManager _applicationManager;
    private readonly ApplicationDbContext _db;
    private readonly ILogger<LoginPostHandler> _logger;
    private readonly IConfiguration _configuration;
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly IHostEnvironment _env;

    public LoginPostHandler(
        SignInManager<IdentityUser> signInManager,
        UserManager<IdentityUser> userManager,
        IClientCookieConfigurationService cookieService,
        IDynamicCookieService dynamicCookieService,
        IOpenIddictApplicationManager applicationManager,
        ApplicationDbContext db,
        ILogger<LoginPostHandler> logger,
        IConfiguration configuration,
        IHttpClientFactory httpClientFactory,
        IHostEnvironment env)
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
    }

    public async Task<IActionResult> Handle(LoginPostRequest request, CancellationToken cancellationToken)
    {
        var http = request.HttpContext;
        var model = request.Model;
        var returnUrl = request.ReturnUrl;
        var clientId = request.ClientId;

        if (ShouldUseRecaptcha())
        {
            var token = http.Request.Form["recaptchaToken"].ToString();
            var recaptchaOk = await VerifyRecaptchaAsync(http, token, "login");
            if (!recaptchaOk)
            {
                var vd = NewViewData();
                vd["ReturnUrl"] = returnUrl;
                vd["ClientId"] = clientId;
                vd["RecaptchaSiteKey"] = _configuration["GoogleReCaptcha:SiteKey"];
                vd.ModelState.AddModelError(string.Empty, "reCAPTCHA verification failed. Please try again.");
                return new ViewResult { ViewName = "Login", ViewData = viewDataWithModel(vd, model) };
            }
        }

        if (string.IsNullOrEmpty(clientId) && !string.IsNullOrEmpty(returnUrl))
        {
            var extracted = TryExtractClientIdFromReturnUrl(returnUrl);
            if (!string.IsNullOrEmpty(extracted))
            {
                clientId = extracted;
                _logger.LogDebug("POST login: extracted client_id '{ClientId}' from returnUrl", clientId);
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

        _logger.LogDebug("Login POST: Email={Email}, ReturnUrl={ReturnUrl}, ClientId={ClientId}", model.Email, returnUrl, clientId);

        // validate
        List<KeyValuePair<string, string>> modelStateErrors = new();
        bool valid = http.Request.HasFormContentType && IsModelStateValid(model, out modelStateErrors);
        if (!valid)
        {
            _logger.LogDebug("Login ModelState invalid");
            var vd = NewViewData();
            foreach (var err in modelStateErrors) vd.ModelState.AddModelError(err.Key, err.Value);
            vd["ReturnUrl"] = returnUrl; vd["ClientId"] = clientId; vd["RecaptchaSiteKey"] = viewData["RecaptchaSiteKey"];
            vd["ClientName"] = clientName;
            return new ViewResult { ViewName = "Login", ViewData = viewDataWithModel(vd, model) };
        }

        if (model.UseCode)
        {
            if (string.IsNullOrWhiteSpace(model.Email) || string.IsNullOrWhiteSpace(model.Code))
            {
                var vd = NewViewData();
                vd.ModelState.AddModelError(string.Empty, "Email and code are required.");
                vd["ReturnUrl"] = returnUrl; vd["ClientId"] = clientId; vd["RecaptchaSiteKey"] = viewData["RecaptchaSiteKey"]; vd["ClientName"] = clientName;
                return new ViewResult { ViewName = "Login", ViewData = viewDataWithModel(vd, model) };
            }

            var user = await _userManager.FindByNameAsync(model.Email) ?? await _userManager.FindByEmailAsync(model.Email);
            if (user == null)
            {
                var vd = NewViewData(); vd.ModelState.AddModelError(string.Empty, "Invalid login attempt.");
                vd["ReturnUrl"] = returnUrl; vd["ClientId"] = clientId; vd["RecaptchaSiteKey"] = viewData["RecaptchaSiteKey"]; vd["ClientName"] = clientName;
                return new ViewResult { ViewName = "Login", ViewData = viewDataWithModel(vd, model) };
            }

            if (!await _userManager.GetTwoFactorEnabledAsync(user))
            {
                var vd = NewViewData(); vd.ModelState.AddModelError(string.Empty, "This account does not allow code-only sign in.");
                vd["ReturnUrl"] = returnUrl; vd["ClientId"] = clientId; vd["RecaptchaSiteKey"] = viewData["RecaptchaSiteKey"]; vd["ClientName"] = clientName;
                return new ViewResult { ViewName = "Login", ViewData = viewDataWithModel(vd, model) };
            }

            var code = (model.Code ?? string.Empty).Replace(" ", string.Empty).Replace("-", string.Empty);
            var isValid = await _userManager.VerifyTwoFactorTokenAsync(user, _userManager.Options.Tokens.AuthenticatorTokenProvider, code);
            if (!isValid)
            {
                var vd = NewViewData(); vd.ModelState.AddModelError(string.Empty, "Invalid code.");
                vd["ReturnUrl"] = returnUrl; vd["ClientId"] = clientId; vd["RecaptchaSiteKey"] = viewData["RecaptchaSiteKey"]; vd["ClientName"] = clientName;
                return new ViewResult { ViewName = "Login", ViewData = viewDataWithModel(vd, model) };
            }

            await _signInManager.SignInAsync(user, isPersistent: model.RememberMe, authenticationMethod: "mfa");

            if (!string.IsNullOrEmpty(clientId))
            {
                try { await _dynamicCookieService.SignInWithClientCookieAsync(clientId, user, model.RememberMe); }
                catch (Exception ex) { _logger.LogWarning(ex, "Failed to sign in with client-specific cookie for client {ClientId}", clientId); }
            }

            if (!string.IsNullOrEmpty(returnUrl))
            {
                if (returnUrl.Contains("/connect/authorize")) return new RedirectResult(returnUrl);
                else if (IsLocalUrl(returnUrl)) return new RedirectResult(returnUrl);
            }
            return new RedirectToActionResult("Index", "Home", null);
        }

        var result = await _signInManager.PasswordSignInAsync(model.Email, model.Password, model.RememberMe, lockoutOnFailure: false);
        _logger.LogDebug("Login attempt result: Success={Success}, Requires2FA={RequiresTwoFactor}", result.Succeeded, result.RequiresTwoFactor);

        if (result.RequiresTwoFactor)
        {
            var redirect = "/mfa/challenge" + (!string.IsNullOrEmpty(returnUrl) ? ($"?returnUrl={Uri.EscapeDataString(returnUrl)}") : string.Empty) + (model.RememberMe ? (string.IsNullOrEmpty(returnUrl) ? "?" : "&") + "RememberMe=true" : string.Empty);
            return new RedirectResult(redirect);
        }
        else if (result.Succeeded)
        {
            var user = await _userManager.FindByNameAsync(model.Email);
            if (user == null)
            {
                var vd = NewViewData(); vd.ModelState.AddModelError(string.Empty, "Authentication error occurred.");
                vd["ReturnUrl"] = returnUrl; vd["ClientId"] = clientId; vd["RecaptchaSiteKey"] = viewData["RecaptchaSiteKey"]; vd["ClientName"] = clientName;
                return new ViewResult { ViewName = "Login", ViewData = viewDataWithModel(vd, model) };
            }

            if (!string.IsNullOrEmpty(clientId))
            {
                try { await _dynamicCookieService.SignInWithClientCookieAsync(clientId, user, model.RememberMe); }
                catch (Exception ex) { _logger.LogWarning(ex, "Failed to sign in with client-specific cookie for client {ClientId}", clientId); }
            }

            if (!string.IsNullOrEmpty(returnUrl))
            {
                if (returnUrl.Contains("/connect/authorize")) return new RedirectResult(returnUrl);
                else if (IsLocalUrl(returnUrl)) return new RedirectResult(returnUrl);
            }
            return new RedirectToActionResult("Index", "Home", null);
        }
        else
        {
            var vd = NewViewData(); vd.ModelState.AddModelError(string.Empty, "Invalid login attempt.");
            vd["ReturnUrl"] = returnUrl; vd["ClientId"] = clientId; vd["RecaptchaSiteKey"] = viewData["RecaptchaSiteKey"]; vd["ClientName"] = clientName;
            return new ViewResult { ViewName = "Login", ViewData = viewDataWithModel(vd, model) };
        }
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

    private async Task<bool> VerifyRecaptchaAsync(HttpContext http, string? token, string actionExpected)
    {
        if (!ShouldUseRecaptcha()) return true;
        var secret = _configuration["GoogleReCaptcha:SecretKey"];
        if (string.IsNullOrWhiteSpace(token)) return false;
        var client = _httpClientFactory.CreateClient();
        var resp = await client.PostAsync("https://www.google.com/recaptcha/api/siteverify", new FormUrlEncodedContent(new Dictionary<string,string>{
            ["secret"] = secret!,
            ["response"] = token,
            ["remoteip"] = http.Connection.RemoteIpAddress?.ToString() ?? string.Empty
        }));
        if (!resp.IsSuccessStatusCode) return false;
        using var s = await resp.Content.ReadAsStreamAsync();
        var result = await JsonSerializer.DeserializeAsync<RecaptchaVerifyResult>(s, new JsonSerializerOptions{ PropertyNameCaseInsensitive = true });
        if (result == null || !result.success) return false;
        var threshold = 0.5;
        var cfgThr = _configuration["GoogleReCaptcha:Threshold"];
        if (double.TryParse(cfgThr, out var t)) threshold = t;
        if (!string.Equals(result.action, actionExpected, StringComparison.OrdinalIgnoreCase)) return false;
        return result.score >= threshold;
    }

    private static bool IsModelStateValid(MrWho.Controllers.LoginViewModel model, out List<KeyValuePair<string, string>> errors)
    {
        errors = new();
        if (model is null) { errors.Add(new("", "Invalid model")); return false; }
        if (!model.UseCode)
        {
            if (string.IsNullOrWhiteSpace(model.Email)) errors.Add(new("Email", "The Email field is required."));
            if (string.IsNullOrWhiteSpace(model.Password)) errors.Add(new("Password", "The Password field is required."));
        }
        else
        {
            if (string.IsNullOrWhiteSpace(model.Email)) errors.Add(new("Email", "The Email field is required."));
            if (string.IsNullOrWhiteSpace(model.Code)) errors.Add(new("Code", "The Code field is required."));
        }
        return errors.Count == 0;
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

    private static bool IsLocalUrl(string? url) => !string.IsNullOrEmpty(url) && url.StartsWith('/') && !url.StartsWith("//") && !url.StartsWith("/\\");

    private record RecaptchaVerifyResult(bool success, double score, string action, string hostname, DateTime challenge_ts, string[]? error_codes);

    private static ViewDataDictionary NewViewData() => new(new EmptyModelMetadataProvider(), new ModelStateDictionary());
    private static ViewDataDictionary viewDataWithModel(ViewDataDictionary vd, object model) { vd.Model = model; return vd; }
}

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

        var externalRegId = http.Session.GetString("ExternalRegistrationId");
        if (!string.IsNullOrWhiteSpace(externalRegId))
        {
            _logger.LogInformation("External RegistrationId found in session during GET logout. Initiating external provider sign-out before local logout.");
            var returnAfterExternal = http.Request.Scheme + "://" + http.Request.Host + "/connect/logout" + new QueryString()
                .Add("clientId", clientId ?? string.Empty)
                .Add("post_logout_redirect_uri", postUri ?? string.Empty).ToUriComponent();
            http.Session.SetString("ExternalSignoutResumeUrl", returnAfterExternal ?? "/");

            var props = new AuthenticationProperties { RedirectUri = "/connect/external/signout-callback" };
            props.Items[OpenIddict.Client.AspNetCore.OpenIddictClientAspNetCoreConstants.Properties.RegistrationId] = externalRegId;
            await http.SignOutAsync(OpenIddict.Client.AspNetCore.OpenIddictClientAspNetCoreDefaults.AuthenticationScheme, props);
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

        var externalRegId = http.Session.GetString("ExternalRegistrationId");
        if (!string.IsNullOrWhiteSpace(externalRegId))
        {
            _logger.LogInformation("External RegistrationId found in session. Initiating external provider sign-out before local logout.");
            var props = new AuthenticationProperties { RedirectUri = "/connect/external/signout-callback" };
            props.Items[OpenIddict.Client.AspNetCore.OpenIddictClientAspNetCoreConstants.Properties.RegistrationId] = externalRegId;
            var resume = UriHelper.GetDisplayUrl(http.Request);
            http.Session.SetString("ExternalSignoutResumeUrl", resume ?? "/");
            await http.SignOutAsync(OpenIddict.Client.AspNetCore.OpenIddictClientAspNetCoreDefaults.AuthenticationScheme, props);
            return new EmptyResult();
        }

        await SignOutFromAllSchemesAsync(http, detectedClientId);

        var candidateUri = postLogoutUri ?? request?.PostLogoutRedirectUri;
        var candidateClientId = clientId ?? request?.ClientId ?? detectedClientId;
        if (!string.IsNullOrEmpty(candidateUri))
        {
            var isValid = await IsPostLogoutRedirectUriValidAsync(candidateClientId, candidateUri);
            if (!isValid)
            {
                string? clientName = null;
                try
                {
                    if (!string.IsNullOrEmpty(candidateClientId))
                    {
                        var app = await _applicationManager.FindByClientIdAsync(candidateClientId);
                        if (app is not null) clientName = await _applicationManager.GetDisplayNameAsync(app);
                    }
                }
                catch { }

                var vd = new ViewDataDictionary(new EmptyModelMetadataProvider(), new ModelStateDictionary())
                {
                    ["ClientName"] = clientName,
                    ["ReturnUrl"] = null,
                    ["LogoutError"] = "You have been signed out, but the redirect URL provided by the application is invalid or not allowed."
                };
                return new ViewResult { ViewName = "LoggedOut", ViewData = vd };
            }
        }

        if (request != null)
        {
            return new SignOutResult(new[] { OpenIddictServerAspNetCoreDefaults.AuthenticationScheme });
        }

        return new RedirectToActionResult("Index", "Home", new { logout = "success" });
    }

    private async Task SignOutFromAllSchemesAsync(HttpContext http, string? clientId)
    {
        try
        {
            await _signInManager.SignOutAsync();
            DeleteCookieAcrossDomains(http, ".AspNetCore.Identity.Application");
            if (!string.IsNullOrEmpty(clientId))
            {
                try { await _dynamicCookieService.SignOutFromClientAsync(clientId); } catch (Exception ex) { _logger.LogWarning(ex, "Failed to sign out from client-specific cookie for client {ClientId}", clientId); }
                try { var cookieName = _cookieService.GetCookieNameForClient(clientId); DeleteCookieAcrossDomains(http, cookieName); } catch { }
            }
            else
            {
                var allConfigurations = _cookieService.GetAllClientConfigurations();
                foreach (var config in allConfigurations)
                {
                    try { await _dynamicCookieService.SignOutFromClientAsync(config.Key); } catch (Exception ex) { _logger.LogDebug(ex, "Failed to sign out from client configuration for client {ClientId}", config.Key); }
                    DeleteCookieAcrossDomains(http, config.Value.CookieName);
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during logout process");
        }
    }

    private void DeleteCookieAcrossDomains(HttpContext http, string cookieName)
    {
        if (string.IsNullOrWhiteSpace(cookieName)) return;
        try
        {
            http.Response.Cookies.Delete(cookieName, new CookieOptions{ Path = "/" });
            var configuredDomain = _configuration["Cookie:Domain"];
            if (!string.IsNullOrWhiteSpace(configuredDomain))
            {
                http.Response.Cookies.Delete(cookieName, new CookieOptions { Domain = configuredDomain, Path = "/" });
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Error deleting cookie {CookieName}", cookieName);
        }
    }

    private async Task<string?> TryGetClientIdFromRequestAsync(HttpContext http)
    {
        try
        {
            var request = http.GetOpenIddictServerRequest();
            if (!string.IsNullOrEmpty(request?.ClientId)) return request.ClientId;
            if (http.Request.Query.TryGetValue("client_id", out var clientIdFromQuery)) return clientIdFromQuery.ToString();
            var clientIdFromCookies = await _cookieService.GetClientIdFromRequestAsync(http);
            if (!string.IsNullOrEmpty(clientIdFromCookies)) return clientIdFromCookies;
            var referer = http.Request.Headers.Referer.ToString();
            if (!string.IsNullOrEmpty(referer) && referer.Contains("client_id="))
            {
                var uri = new Uri(referer);
                var query = System.Web.HttpUtility.ParseQueryString(uri.Query);
                var clientIdFromReferer = query["client_id"];
                if (!string.IsNullOrEmpty(clientIdFromReferer)) return clientIdFromReferer;
            }
            return null;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Error attempting to detect ClientId from request");
            return null;
        }
    }

    private async Task<bool> IsPostLogoutRedirectUriValidAsync(string? clientId, string? uri)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(uri)) return true;
            if (string.IsNullOrWhiteSpace(clientId)) return false;
            var application = await _applicationManager.FindByClientIdAsync(clientId);
            if (application is null) return false;
            try
            {
                dynamic dynManager = _applicationManager;
                var uris = await dynManager.GetPostLogoutRedirectUrisAsync(application);
                if (uris is IEnumerable<string> list)
                {
                    return list.Any(allowed => string.Equals(allowed?.TrimEnd('/'), uri.TrimEnd('/'), StringComparison.OrdinalIgnoreCase));
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Could not retrieve post-logout redirect URIs via manager API; treating as invalid");
                return false;
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Error validating post_logout_redirect_uri");
        }
        return false;
    }
}

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

        var externalRegId = http.Session.GetString("ExternalRegistrationId");
        if (!string.IsNullOrWhiteSpace(externalRegId))
        {
            _logger.LogInformation("External RegistrationId found in session during POST logout. Initiating external provider sign-out before local logout.");
            var props = new AuthenticationProperties { RedirectUri = "/connect/external/signout-callback" };
            props.Items[OpenIddict.Client.AspNetCore.OpenIddictClientAspNetCoreConstants.Properties.RegistrationId] = externalRegId;
            await http.SignOutAsync(OpenIddict.Client.AspNetCore.OpenIddictClientAspNetCoreDefaults.AuthenticationScheme, props);
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

public sealed class AccessDeniedGetHandler : IRequestHandler<AccessDeniedGetRequest, IActionResult>
{
    private readonly IOpenIddictApplicationManager _applicationManager;
    private readonly ILogger<AccessDeniedGetHandler> _logger;

    public AccessDeniedGetHandler(IOpenIddictApplicationManager applicationManager, ILogger<AccessDeniedGetHandler> logger)
    {
        _applicationManager = applicationManager;
        _logger = logger;
    }

    public async Task<IActionResult> Handle(AccessDeniedGetRequest request, CancellationToken cancellationToken)
    {
        var http = request.HttpContext;
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

        vd["ClientName"] = clientName;
        return new ViewResult { ViewName = "AccessDenied", ViewData = vd };
    }
}

public sealed class RegisterGetHandler : IRequestHandler<RegisterGetRequest, IActionResult>
{
    private readonly IConfiguration _configuration;
    private readonly IHostEnvironment _env;

    public RegisterGetHandler(IConfiguration configuration, IHostEnvironment env)
    {
        _configuration = configuration;
        _env = env;
    }

    public Task<IActionResult> Handle(RegisterGetRequest request, CancellationToken cancellationToken)
    {
        var vd = new ViewDataDictionary(new EmptyModelMetadataProvider(), new ModelStateDictionary())
        {
            ["RecaptchaSiteKey"] = ShouldUseRecaptcha() ? _configuration["GoogleReCaptcha:SiteKey"] : null
        };
        return Task.FromResult<IActionResult>(new ViewResult { ViewName = "Register", ViewData = new ViewDataDictionary(vd) { Model = new RegisterUserRequest() } });
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
}

public sealed class RegisterPostHandler : IRequestHandler<RegisterPostRequest, IActionResult>
{
    private readonly UserManager<IdentityUser> _userManager;
    private readonly ApplicationDbContext _db;
    private readonly IConfiguration _configuration;
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly IHostEnvironment _env;

    public RegisterPostHandler(UserManager<IdentityUser> userManager, ApplicationDbContext db, IConfiguration configuration, IHttpClientFactory httpClientFactory, IHostEnvironment env)
    {
        _userManager = userManager;
        _db = db;
        _configuration = configuration;
        _httpClientFactory = httpClientFactory;
        _env = env;
    }

    public async Task<IActionResult> Handle(RegisterPostRequest request, CancellationToken cancellationToken)
    {
        var http = request.HttpContext;
        var input = request.Input;

        var token = http.Request.Form["recaptchaToken"].ToString();
        var recaptchaOk = await VerifyRecaptchaAsync(http, token, "register");
        if (!recaptchaOk)
        {
            var vd = new ViewDataDictionary(new EmptyModelMetadataProvider(), new ModelStateDictionary())
            {
                ["RecaptchaSiteKey"] = ShouldUseRecaptcha() ? _configuration["GoogleReCaptcha:SiteKey"] : null
            };
            vd.ModelState.AddModelError(string.Empty, "reCAPTCHA verification failed. Please try again.");
            return new ViewResult { ViewName = "Register", ViewData = new ViewDataDictionary(vd) { Model = input } };
        }

        // Minimal validation; in MVC this would be ModelState.IsValid
        if (string.IsNullOrWhiteSpace(input.Email) || string.IsNullOrWhiteSpace(input.Password) || string.IsNullOrWhiteSpace(input.FirstName) || string.IsNullOrWhiteSpace(input.LastName))
        {
            var vd = new ViewDataDictionary(new EmptyModelMetadataProvider(), new ModelStateDictionary())
            {
                ["RecaptchaSiteKey"] = ShouldUseRecaptcha() ? _configuration["GoogleReCaptcha:SiteKey"] : null
            };
            return new ViewResult { ViewName = "Register", ViewData = new ViewDataDictionary(vd) { Model = input } };
        }

        var existingByEmail = await _userManager.FindByEmailAsync(input.Email);
        if (existingByEmail != null)
        {
            var vd = new ViewDataDictionary(new EmptyModelMetadataProvider(), new ModelStateDictionary())
            {
                ["RecaptchaSiteKey"] = ShouldUseRecaptcha() ? _configuration["GoogleReCaptcha:SiteKey"] : null
            };
            vd.ModelState.AddModelError("Email", "An account with this email already exists.");
            return new ViewResult { ViewName = "Register", ViewData = new ViewDataDictionary(vd) { Model = input } };
        }

        var user = new IdentityUser { UserName = input.Email, Email = input.Email, EmailConfirmed = false };
        var result = await _userManager.CreateAsync(user, input.Password);
        if (!result.Succeeded)
        {
            var vd = new ViewDataDictionary(new EmptyModelMetadataProvider(), new ModelStateDictionary())
            {
                ["RecaptchaSiteKey"] = ShouldUseRecaptcha() ? _configuration["GoogleReCaptcha:SiteKey"] : null
            };
            foreach (var error in result.Errors) vd.ModelState.AddModelError(string.Empty, error.Description);
            return new ViewResult { ViewName = "Register", ViewData = new ViewDataDictionary(vd) { Model = input } };
        }

        var profile = new UserProfile
        {
            UserId = user.Id,
            FirstName = input.FirstName,
            LastName = input.LastName,
            DisplayName = $"{input.FirstName} {input.LastName}".Trim(),
            State = UserState.New,
            CreatedAt = DateTime.UtcNow
        };
        _db.UserProfiles.Add(profile);
        await _db.SaveChangesAsync(cancellationToken);

        return new RedirectToActionResult("RegisterSuccess", "Auth", null);
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

    private async Task<bool> VerifyRecaptchaAsync(HttpContext http, string? token, string actionExpected)
    {
        if (!ShouldUseRecaptcha()) return true;
        var secret = _configuration["GoogleReCaptcha:SecretKey"];
        if (string.IsNullOrWhiteSpace(token)) return false;
        var client = _httpClientFactory.CreateClient();
        var resp = await client.PostAsync("https://www.google.com/recaptcha/api/siteverify", new FormUrlEncodedContent(new Dictionary<string,string>{
            ["secret"] = secret!,
            ["response"] = token,
            ["remoteip"] = http.Connection.RemoteIpAddress?.ToString() ?? string.Empty
        }));
        if (!resp.IsSuccessStatusCode) return false;
        using var s = await resp.Content.ReadAsStreamAsync();
        var result = await JsonSerializer.DeserializeAsync<RecaptchaVerifyResult>(s, new JsonSerializerOptions{ PropertyNameCaseInsensitive = true });
        if (result == null || !result.success) return false;
        var threshold = 0.5;
        var cfgThr = _configuration["GoogleReCaptcha:Threshold"];
        if (double.TryParse(cfgThr, out var t)) threshold = t;
        if (!string.Equals(result.action, actionExpected, StringComparison.OrdinalIgnoreCase)) return false;
        return result.score >= threshold;
    }

    private record RecaptchaVerifyResult(bool success, double score, string action, string hostname, DateTime challenge_ts, string[]? error_codes);
}

public sealed class RegisterSuccessGetHandler : IRequestHandler<RegisterSuccessGetRequest, IActionResult>
{
    public Task<IActionResult> Handle(RegisterSuccessGetRequest request, CancellationToken cancellationToken)
    {
        return Task.FromResult<IActionResult>(new ViewResult { ViewName = "RegisterSuccess" });
    }
}
