using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ModelBinding;
using Microsoft.AspNetCore.Mvc.ViewFeatures;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using MrWho.Data;
using MrWho.Models;
using MrWho.Services.Mediator;
using MrWho.Shared.Models;
using System.Net.Http;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;

namespace MrWho.Endpoints.Auth;

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

        var profile = new MrWho.Models.UserProfile
        {
            UserId = user.Id,
            FirstName = input.FirstName,
            LastName = input.LastName,
            DisplayName = $"{input.FirstName} {input.LastName}".Trim(),
            State = MrWho.Models.UserState.New,
            CreatedAt = DateTime.UtcNow
        };
        _db.UserProfiles.Add(profile);
        await _db.SaveChangesAsync(cancellationToken);

        // Link user to client if we have a hint (either direct clientId or via returnUrl's client_id)
        try
        {
            var formClientId = http.Request.Form["clientId"].ToString();
            var returnUrl = http.Request.Form["returnUrl"].ToString();
            var clientHint = !string.IsNullOrWhiteSpace(formClientId) ? formClientId : TryExtractClientIdFromReturnUrl(returnUrl);
            if (!string.IsNullOrWhiteSpace(clientHint))
            {
                var client = await _db.Clients.FirstOrDefaultAsync(c => c.Id == clientHint || c.ClientId == clientHint, cancellationToken);
                if (client != null)
                {
                    var exists = await _db.ClientUsers.AnyAsync(cu => cu.ClientId == client.Id && cu.UserId == user.Id, cancellationToken);
                    if (!exists)
                    {
                        _db.ClientUsers.Add(new ClientUser
                        {
                            ClientId = client.Id,
                            UserId = user.Id,
                            CreatedAt = DateTime.UtcNow,
                            CreatedBy = user.UserName
                        });
                        await _db.SaveChangesAsync(cancellationToken);
                    }
                }
            }
        }
        catch
        {
            // best-effort only; ignore failures to keep registration flow resilient
        }

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
}
