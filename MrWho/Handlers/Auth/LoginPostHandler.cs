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

namespace MrWho.Handlers.Auth;

public sealed class LoginPostHandler : IRequestHandler<MrWho.Endpoints.Auth.LoginPostRequest, IActionResult>
{
    private readonly SignInManager<IdentityUser> _signInManager;
    private readonly UserManager<IdentityUser> _userManager;
    private readonly IClientCookieConfigurationService _cookieService;
    private readonly IDynamicCookieService _dynamicCookieService;
    private readonly ApplicationDbContext _db;
    private readonly ILogger<LoginPostHandler> _logger;
    private readonly ILoginHelper _loginHelper;
    private readonly IUserRealmValidationService _realmValidationService; // added

    public LoginPostHandler(
        SignInManager<IdentityUser> signInManager,
        UserManager<IdentityUser> userManager,
        IClientCookieConfigurationService cookieService,
        IDynamicCookieService dynamicCookieService,
        ApplicationDbContext db,
        ILogger<LoginPostHandler> logger,
        ILoginHelper loginHelper,
        IUserRealmValidationService realmValidationService) // added
    {
        _signInManager = signInManager;
        _userManager = userManager;
        _cookieService = cookieService;
        _dynamicCookieService = dynamicCookieService;
        _db = db;
        _logger = logger;
        _loginHelper = loginHelper;
        _realmValidationService = realmValidationService; // added
    }

    public async Task<IActionResult> Handle(MrWho.Endpoints.Auth.LoginPostRequest request, CancellationToken cancellationToken)
    {
        var http = request.HttpContext;
        var model = request.Model;
        var returnUrl = request.ReturnUrl;
        var clientId = request.ClientId;

        if (_loginHelper.ShouldUseRecaptcha())
        {
            var token = http.Request.Form["recaptchaToken"].ToString();
            var recaptchaOk = await _loginHelper.VerifyRecaptchaAsync(http, token, "login");
            if (!recaptchaOk)
            {
                var vd = NewViewData();
                vd["ReturnUrl"] = returnUrl;
                vd["ClientId"] = clientId;
                vd["RecaptchaSiteKey"] = _loginHelper.GetRecaptchaSiteKey();
                vd.ModelState.AddModelError(string.Empty, "reCAPTCHA verification failed. Please try again.");
                return new ViewResult { ViewName = "Login", ViewData = viewDataWithModel(vd, model) };
            }
        }

        if (string.IsNullOrEmpty(clientId) && !string.IsNullOrEmpty(returnUrl))
        {
            var extracted = _loginHelper.TryExtractClientIdFromReturnUrl(returnUrl);
            if (!string.IsNullOrEmpty(extracted))
            {
                clientId = extracted;
                _logger.LogDebug("POST login: extracted client_id '{ClientId}' from returnUrl", clientId);
            }
        }

        var viewData = NewViewData();
        viewData["ReturnUrl"] = returnUrl;
        viewData["ClientId"] = clientId;
        viewData["RecaptchaSiteKey"] = _loginHelper.GetRecaptchaSiteKey();

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
            foreach (var err in modelStateErrors)
            {
                vd.ModelState.AddModelError(err.Key, err.Value);
            }

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

            // Realm/policy validation after successful sign-in
            if (!string.IsNullOrEmpty(clientId))
            {
                try
                {
                    var realmValidation = await _realmValidationService.ValidateUserRealmAccessAsync(user, clientId);
                    if (!realmValidation.IsValid)
                    {
                        _logger.LogWarning("Login denied for user {User} to client {ClientId} (code login). Reason: {Reason}", user.UserName, clientId, realmValidation.Reason);
                        try { await _dynamicCookieService.SignOutFromClientAsync(clientId); } catch { }
                        await _signInManager.SignOutAsync();
                        return new RedirectResult(BuildAccessDeniedUrl(returnUrl, clientId));
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error during realm validation for user {User} and client {ClientId} (code login)", user.Id, clientId);
                    try { await _dynamicCookieService.SignOutFromClientAsync(clientId); } catch { }
                    await _signInManager.SignOutAsync();
                    return new RedirectResult(BuildAccessDeniedUrl(returnUrl, clientId));
                }
            }

            if (!string.IsNullOrEmpty(clientId))
            {
                try { await _dynamicCookieService.SignInWithClientCookieAsync(clientId, user, model.RememberMe); }
                catch (Exception ex) { _logger.LogWarning(ex, "Failed to sign in with client-specific cookie for client {ClientId}", clientId); }
            }

            if (!string.IsNullOrEmpty(returnUrl))
            {
                if (returnUrl.Contains("/connect/authorize"))
                {
                    return new RedirectResult(returnUrl);
                }
                else if (_loginHelper.IsLocalUrl(returnUrl))
                {
                    return new RedirectResult(returnUrl);
                }
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

            // Realm/policy validation after successful sign-in
            if (!string.IsNullOrEmpty(clientId))
            {
                try
                {
                    var realmValidation = await _realmValidationService.ValidateUserRealmAccessAsync(user, clientId);
                    if (!realmValidation.IsValid)
                    {
                        _logger.LogWarning("Login denied for user {User} to client {ClientId}. Reason: {Reason}", user.UserName, clientId, realmValidation.Reason);
                        try { await _dynamicCookieService.SignOutFromClientAsync(clientId); } catch { }
                        await _signInManager.SignOutAsync();
                        return new RedirectResult(BuildAccessDeniedUrl(returnUrl, clientId));
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error during realm validation for user {User} and client {ClientId}", user.Id, clientId);
                    try { await _dynamicCookieService.SignOutFromClientAsync(clientId); } catch { }
                    await _signInManager.SignOutAsync();
                    return new RedirectResult(BuildAccessDeniedUrl(returnUrl, clientId));
                }
            }

            if (!string.IsNullOrEmpty(clientId))
            {
                try { await _dynamicCookieService.SignInWithClientCookieAsync(clientId, user, model.RememberMe); }
                catch (Exception ex) { _logger.LogWarning(ex, "Failed to sign in with client-specific cookie for client {ClientId}", clientId); }
            }

            if (!string.IsNullOrEmpty(returnUrl))
            {
                if (returnUrl.Contains("/connect/authorize"))
                {
                    return new RedirectResult(returnUrl);
                }
                else if (_loginHelper.IsLocalUrl(returnUrl))
                {
                    return new RedirectResult(returnUrl);
                }
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

    private static string BuildAccessDeniedUrl(string? returnUrl, string? clientId)
    {
        var ret = !string.IsNullOrEmpty(returnUrl) ? Uri.EscapeDataString(returnUrl) : string.Empty;
        var cid = !string.IsNullOrEmpty(clientId) ? Uri.EscapeDataString(clientId) : string.Empty;
        var url = "/connect/access-denied";
        var hasQuery = false;
        if (!string.IsNullOrEmpty(ret)) { url += $"?returnUrl={ret}"; hasQuery = true; }
        if (!string.IsNullOrEmpty(cid)) { url += hasQuery ? $"&clientId={cid}" : $"?clientId={cid}"; }
        return url;
    }

    private static bool IsModelStateValid(MrWho.Controllers.LoginViewModel model, out List<KeyValuePair<string, string>> errors)
    {
        errors = new();
        if (model is null) { errors.Add(new("", "Invalid model")); return false; }
        if (!model.UseCode)
        {
            if (string.IsNullOrWhiteSpace(model.Email))
            {
                errors.Add(new("Email", "The Email field is required."));
            }

            if (string.IsNullOrWhiteSpace(model.Password))
            {
                errors.Add(new("Password", "The Password field is required."));
            }
        }
        else
        {
            if (string.IsNullOrWhiteSpace(model.Email))
            {
                errors.Add(new("Email", "The Email field is required."));
            }

            if (string.IsNullOrWhiteSpace(model.Code))
            {
                errors.Add(new("Code", "The Code field is required."));
            }
        }
        return errors.Count == 0;
    }

    private static ViewDataDictionary NewViewData() => new(new EmptyModelMetadataProvider(), new ModelStateDictionary());
    private static ViewDataDictionary viewDataWithModel(ViewDataDictionary vd, object model) { vd.Model = model; return vd; }
}
