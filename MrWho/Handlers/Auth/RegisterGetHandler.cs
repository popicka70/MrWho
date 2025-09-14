using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ModelBinding;
using Microsoft.AspNetCore.Mvc.ViewFeatures;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using MrWho.Data;
using MrWho.Options;
using MrWho.Services.Mediator;
using MrWho.Shared.Models;

namespace MrWho.Handlers.Auth;

public sealed class RegisterGetHandler : IRequestHandler<MrWho.Endpoints.Auth.RegisterGetRequest, IActionResult>
{
    private readonly IConfiguration _configuration;
    private readonly IHostEnvironment _env;
    private readonly ApplicationDbContext _db;
    private readonly IOptions<MrWhoOptions> _mrWhoOptions;

    public RegisterGetHandler(IConfiguration configuration, IHostEnvironment env, ApplicationDbContext db, IOptions<MrWhoOptions> mrWhoOptions)
    {
        _configuration = configuration;
        _env = env;
        _db = db;
        _mrWhoOptions = mrWhoOptions;
    }

    public async Task<IActionResult> Handle(MrWho.Endpoints.Auth.RegisterGetRequest request, CancellationToken cancellationToken)
    {
        var http = request.HttpContext;

        // Capture context so the form can POST it back
        var returnUrl = http.Request.Query["returnUrl"].ToString();
        var clientId = http.Request.Query["clientId"].ToString();
        if (string.IsNullOrEmpty(clientId) && !string.IsNullOrEmpty(returnUrl))
        {
            clientId = TryExtractClientIdFromReturnUrl(returnUrl) ?? clientId;
        }

        var vd = new ViewDataDictionary(new EmptyModelMetadataProvider(), new ModelStateDictionary())
        {
            ["RecaptchaSiteKey"] = ShouldUseRecaptcha() ? _configuration["GoogleReCaptcha:SiteKey"] : null,
            ["ReturnUrl"] = returnUrl,
            ["ClientId"] = clientId
        };

        // Compute theme and logo similar to Login
        try
        {
            string? themeName = null;
            string? customCssUrl = null;
            string? logoUri = null;
            string? clientName = null;

            if (!string.IsNullOrEmpty(clientId))
            {
                var client = await _db.Clients
                    .AsNoTracking()
                    .Include(c => c.Realm)
                    .FirstOrDefaultAsync(c => c.ClientId == clientId, cancellationToken);
                if (client != null)
                {
                    clientName = client.Name ?? client.ClientId;
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
                    catch { /* ignore */ }
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

            if (!string.IsNullOrWhiteSpace(themeName)) vd["ThemeName"] = themeName;
            if (!string.IsNullOrWhiteSpace(customCssUrl)) vd["CustomCssUrl"] = customCssUrl;
            if (!string.IsNullOrWhiteSpace(logoUri)) vd["LogoUri"] = logoUri;
            if (!string.IsNullOrWhiteSpace(clientName)) vd["ClientName"] = clientName;
        }
        catch { /* ignore theme errors */ }

        return new ViewResult { ViewName = "Register", ViewData = new ViewDataDictionary(vd) { Model = new RegisterUserRequest() } };
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
}
