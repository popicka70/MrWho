using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ModelBinding;
using Microsoft.AspNetCore.Mvc.ViewFeatures;
using Microsoft.EntityFrameworkCore;
using MrWho.Data;
using MrWho.Services;
using MrWho.Services.Mediator;
using OpenIddict.Abstractions;
using System.Security.Claims;
using Microsoft.AspNetCore.WebUtilities;

namespace MrWho.Handlers.Auth;

public sealed record ConsentGetRequest(HttpContext HttpContext, string ReturnUrl, string ClientId) : IRequest<IActionResult>;
public sealed record ConsentPostRequest(HttpContext HttpContext, string ReturnUrl, string ClientId, string[] Scopes, bool Remember) : IRequest<IActionResult>;
public sealed record ConsentForgetRequest(HttpContext HttpContext, string ClientId) : IRequest<IActionResult>;

public sealed class ConsentGetHandler : IRequestHandler<ConsentGetRequest, IActionResult>
{
    private readonly ApplicationDbContext _db;
    private readonly IConsentService _consentService;
    private readonly ILogger<ConsentGetHandler> _logger;

    public ConsentGetHandler(ApplicationDbContext db, IConsentService consentService, ILogger<ConsentGetHandler> logger)
    {
        _db = db;
        _consentService = consentService;
        _logger = logger;
    }

    public async Task<IActionResult> Handle(ConsentGetRequest request, CancellationToken cancellationToken)
    {
        var vd = new ViewDataDictionary(new EmptyModelMetadataProvider(), new ModelStateDictionary());
        vd["ReturnUrl"] = request.ReturnUrl;
        vd["ClientId"] = request.ClientId;

        var client = await _db.Clients.AsNoTracking().Include(c=>c.Realm).FirstOrDefaultAsync(c => c.ClientId == request.ClientId, cancellationToken);
        if (client != null)
        {
            vd["ClientName"] = client.Name ?? request.ClientId;
            vd["ThemeName"] = client.ThemeName ?? client.Realm?.DefaultThemeName;
        }

        // Parse requested scopes from the returnUrl (authorize request)
        try
        {
            var uri = new Uri(request.ReturnUrl);
            var q = QueryHelpers.ParseQuery(uri.Query);
            var scopeParam = q.TryGetValue(OpenIddictConstants.Parameters.Scope, out var sv) ? sv.ToString() : string.Empty;
            var requestedScopes = scopeParam.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

            var userId = request.HttpContext.User.FindFirstValue(OpenIddictConstants.Claims.Subject) ?? request.HttpContext.User.FindFirstValue(ClaimTypes.NameIdentifier);
            var existing = userId == null ? null : await _consentService.GetAsync(userId, request.ClientId, cancellationToken);
            var alreadyGranted = existing?.GetGrantedScopes() ?? Array.Empty<string>();
            var missing = _consentService.DiffMissingScopes(requestedScopes, alreadyGranted);

            vd["RequestedScopes"] = requestedScopes;
            vd["AlreadyGranted"] = alreadyGranted.ToArray();
            vd["MissingScopes"] = missing.ToArray();
        }
        catch
        {
            vd["RequestedScopes"] = Array.Empty<string>();
            vd["AlreadyGranted"] = Array.Empty<string>();
            vd["MissingScopes"] = Array.Empty<string>();
        }

        return new ViewResult { ViewName = "Consent", ViewData = vd };
    }
}

public sealed class ConsentPostHandler : IRequestHandler<ConsentPostRequest, IActionResult>
{
    private readonly IConsentService _consentService;
    private readonly ILogger<ConsentPostHandler> _logger;

    public ConsentPostHandler(IConsentService consentService, ILogger<ConsentPostHandler> logger)
    {
        _consentService = consentService;
        _logger = logger;
    }

    public async Task<IActionResult> Handle(ConsentPostRequest request, CancellationToken cancellationToken)
    {
        var userId = request.HttpContext.User.FindFirstValue(OpenIddictConstants.Claims.Subject) ?? request.HttpContext.User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (userId == null)
        {
            return new UnauthorizedResult();
        }

        var granted = request.Scopes ?? Array.Empty<string>();
        if (request.Remember)
        {
            await _consentService.GrantAsync(userId, request.ClientId, granted, cancellationToken);
        }

        // Append a one-time approval flag to avoid re-prompt loop when Remember is unchecked
        string returnUrl = request.ReturnUrl;
        try
        {
            var uri = new Uri(returnUrl);
            var q = QueryHelpers.ParseQuery(uri.Query);
            var dict = q.ToDictionary(k => k.Key, v => v.Value.ToString());
            dict["mrwho_consent"] = "ok";
            var newQuery = QueryString.Create(dict);
            var ub = new UriBuilder(uri) { Query = newQuery.ToUriComponent().TrimStart('?') };
            returnUrl = ub.Uri.ToString();
        }
        catch { /* ignore malformed URL; just use original */ }

        return new RedirectResult(returnUrl);
    }
}

public sealed class ConsentForgetHandler : IRequestHandler<ConsentForgetRequest, IActionResult>
{
    private readonly IConsentService _consentService;

    public ConsentForgetHandler(IConsentService consentService)
    {
        _consentService = consentService;
    }

    public async Task<IActionResult> Handle(ConsentForgetRequest request, CancellationToken cancellationToken)
    {
        var userId = request.HttpContext.User.FindFirstValue(OpenIddictConstants.Claims.Subject) ?? request.HttpContext.User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (userId == null)
        {
            return new UnauthorizedResult();
        }

        await _consentService.ForgetAsync(userId, request.ClientId, cancellationToken);
        return new OkResult();
    }
}
