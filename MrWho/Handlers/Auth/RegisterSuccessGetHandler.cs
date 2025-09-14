using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using MrWho.Data;
using MrWho.Options;
using MrWho.Services.Mediator;

namespace MrWho.Handlers.Auth;

public sealed class RegisterSuccessGetHandler : IRequestHandler<MrWho.Endpoints.Auth.RegisterSuccessGetRequest, IActionResult>
{
    private readonly ApplicationDbContext _db;
    private readonly IOptions<MrWhoOptions> _mrWhoOptions;

    public RegisterSuccessGetHandler(ApplicationDbContext db, IOptions<MrWhoOptions> mrWhoOptions)
    {
        _db = db;
        _mrWhoOptions = mrWhoOptions;
    }

    public async Task<IActionResult> Handle(MrWho.Endpoints.Auth.RegisterSuccessGetRequest request, CancellationToken cancellationToken)
    {
        var http = request.HttpContext;
        var returnUrl = http.Request.Query["returnUrl"].ToString();
        var clientId = http.Request.Query["clientId"].ToString();

        var vd = new Microsoft.AspNetCore.Mvc.ViewFeatures.ViewDataDictionary(new Microsoft.AspNetCore.Mvc.ModelBinding.EmptyModelMetadataProvider(), new Microsoft.AspNetCore.Mvc.ModelBinding.ModelStateDictionary())
        {
            ["ReturnUrl"] = returnUrl,
            ["ClientId"] = clientId
        };

        // Compute theme with client/realm precedence
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
                    if (showClientLogo && !string.IsNullOrWhiteSpace(clientLogo)) {
                        logoUri = clientLogo;
                    }
                    else if (!string.IsNullOrWhiteSpace(client.Realm?.RealmLogoUri)) {
                        logoUri = client.Realm!.RealmLogoUri;
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

            if (!string.IsNullOrWhiteSpace(themeName)) {
                vd["ThemeName"] = themeName;
            }

            if (!string.IsNullOrWhiteSpace(customCssUrl)) {
                vd["CustomCssUrl"] = customCssUrl;
            }

            if (!string.IsNullOrWhiteSpace(logoUri)) {
                vd["LogoUri"] = logoUri;
            }

            if (!string.IsNullOrWhiteSpace(clientName)) {
                vd["ClientName"] = clientName;
            }
        }
        catch { }

        return new ViewResult { ViewName = "RegisterSuccess", ViewData = vd };
    }
}
