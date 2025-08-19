using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ModelBinding;
using Microsoft.AspNetCore.Mvc.ViewFeatures;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using MrWho.Data;
using MrWho.Services;
using MrWho.Services.Mediator;
using System.Net.Http;
using System.Text.Json;

namespace MrWho.Endpoints.Auth;

public sealed class LoginPostHandler : IRequestHandler<LoginPostRequest, IActionResult>
{
    private readonly SignInManager<IdentityUser> _signInManager;
    private readonly UserManager<IdentityUser> _userManager;
    private readonly IClientCookieConfigurationService _cookieService;
    private readonly IDynamicCookieService _dynamicCookieService;
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
                // Optional: resolve client display name if needed later
                clientName = clientId;
            }
            catch { }
        }
        viewData["ClientName"] = clientName;

        _logger.LogDebug("Login POST: Email={Email}, ReturnUrl={ReturnUrl}, ClientId={ClientId}", model.Email, returnUrl, clientId);

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
        var result = await System.Text.Json.JsonSerializer.DeserializeAsync<RecaptchaVerifyResult>(s, new System.Text.Json.JsonSerializerOptions{ PropertyNameCaseInsensitive = true });
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
