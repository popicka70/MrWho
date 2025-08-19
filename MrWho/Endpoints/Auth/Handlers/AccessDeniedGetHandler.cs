using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ModelBinding;
using Microsoft.AspNetCore.Mvc.ViewFeatures;
using MrWho.Services.Mediator;
using OpenIddict.Abstractions;

namespace MrWho.Endpoints.Auth;

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
