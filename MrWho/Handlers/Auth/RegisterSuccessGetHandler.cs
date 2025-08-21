using Microsoft.AspNetCore.Mvc;
using MrWho.Services.Mediator;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using MrWho.Data;
using MrWho.Options;

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
        var vd = new Microsoft.AspNetCore.Mvc.ViewFeatures.ViewDataDictionary(new Microsoft.AspNetCore.Mvc.ModelBinding.EmptyModelMetadataProvider(), new Microsoft.AspNetCore.Mvc.ModelBinding.ModelStateDictionary());

        // Optionally theme by clientId if present in query (readable via HttpContext from Controller, but we don't have it here)
        // Keep it simple: just set defaults to ensure themed layout still loads
        try
        {
            var themeName = _mrWhoOptions.Value.DefaultThemeName;
            if (!string.IsNullOrWhiteSpace(themeName)) vd["ThemeName"] = themeName;
        }
        catch { }

        return new ViewResult { ViewName = "RegisterSuccess", ViewData = vd };
    }
}
