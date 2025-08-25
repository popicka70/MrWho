using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ViewFeatures;
using Microsoft.AspNetCore.Mvc.ModelBinding;
using MrWho.Services;
using MrWho.Services.Mediator;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using MrWho.Data;
using MrWho.Options;

namespace MrWho.Handlers.Auth;

public sealed class LogoutGetHandler : IRequestHandler<MrWho.Endpoints.Auth.LogoutGetRequest, IActionResult>
{
    private readonly ILogger<LogoutGetHandler> _logger;
    private readonly ILogoutHelper _logoutHelper;
    private readonly ApplicationDbContext _db;
    private readonly IOptions<MrWhoOptions> _mrWhoOptions;

    public LogoutGetHandler(ILogger<LogoutGetHandler> logger, ILogoutHelper logoutHelper, ApplicationDbContext db, IOptions<MrWhoOptions> mrWhoOptions)
    { _logger = logger; _logoutHelper = logoutHelper; _db = db; _mrWhoOptions = mrWhoOptions; }

    public async Task<IActionResult> Handle(MrWho.Endpoints.Auth.LogoutGetRequest request, CancellationToken cancellationToken)
    {
        var http = request.HttpContext;
        var clientId = request.ClientId;
        var postUri = request.PostLogoutRedirectUri;
        _logger.LogInformation("GET logout invoked client={ClientId}", clientId);

        await _logoutHelper.SignOutAsync(http);

        var vd = new ViewDataDictionary(new EmptyModelMetadataProvider(), new ModelStateDictionary())
        {
            ["ClientId"] = clientId,
            ["ReturnUrl"] = postUri
        };

        try
        {
            if (!string.IsNullOrEmpty(clientId))
            {
                var client = await _db.Clients.AsNoTracking().Include(c => c.Realm).FirstOrDefaultAsync(c => c.ClientId == clientId, cancellationToken);
                if (client != null)
                {
                    vd["ClientName"] = client.Name ?? client.ClientId;
                    var theme = client.ThemeName ?? client.Realm?.DefaultThemeName ?? _mrWhoOptions.Value.DefaultThemeName;
                    if (!string.IsNullOrWhiteSpace(theme)) vd["ThemeName"] = theme;
                }
            }
        }
        catch { }

        return new ViewResult { ViewName = "LoggedOut", ViewData = vd };
    }
}
