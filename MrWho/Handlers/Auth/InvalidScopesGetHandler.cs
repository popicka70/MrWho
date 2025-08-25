using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ModelBinding;
using Microsoft.AspNetCore.Mvc.ViewFeatures;
using MrWho.Services.Mediator;
using Microsoft.EntityFrameworkCore;
using MrWho.Data;
using Microsoft.Extensions.Options;
using MrWho.Options;

namespace MrWho.Handlers.Auth;

public sealed record InvalidScopesGetRequest(HttpContext HttpContext, string? ReturnUrl, string? ClientId, string? Missing, string? Requested) : IRequest<IActionResult>;

public sealed class InvalidScopesGetHandler : IRequestHandler<InvalidScopesGetRequest, IActionResult>
{
    private readonly ApplicationDbContext _db;
    private readonly IOptions<MrWhoOptions> _opts;
    private readonly ILogger<InvalidScopesGetHandler> _logger;

    public InvalidScopesGetHandler(ApplicationDbContext db, IOptions<MrWhoOptions> opts, ILogger<InvalidScopesGetHandler> logger)
    {
        _db = db;
        _opts = opts;
        _logger = logger;
    }

    public async Task<IActionResult> Handle(InvalidScopesGetRequest request, CancellationToken cancellationToken)
    {
        var vd = new ViewDataDictionary(new EmptyModelMetadataProvider(), new ModelStateDictionary());
        vd["ReturnUrl"] = request.ReturnUrl;
        vd["ClientId"] = request.ClientId;
        vd["MissingScopes"] = (request.Missing ?? string.Empty).Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        vd["RequestedScopes"] = (request.Requested ?? string.Empty).Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

        if (!string.IsNullOrWhiteSpace(request.ClientId))
        {
            try
            {
                var client = await _db.Clients.AsNoTracking().Include(c => c.Scopes).Include(c=>c.Realm)
                    .FirstOrDefaultAsync(c => c.ClientId == request.ClientId, cancellationToken);
                if (client != null)
                {
                    vd["AllowedScopes"] = client.Scopes.Select(s => s.Scope).OrderBy(s=>s).ToList();
                    vd["ClientName"] = client.Name ?? request.ClientId;
                    vd["ThemeName"] = client.ThemeName ?? client.Realm?.DefaultThemeName ?? _opts.Value.DefaultThemeName;
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Failed to load client for invalid scopes page");
            }
        }
        return new ViewResult { ViewName = "InvalidScopes", ViewData = vd };
    }
}
