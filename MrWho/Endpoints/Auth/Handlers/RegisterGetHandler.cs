using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ModelBinding;
using Microsoft.AspNetCore.Mvc.ViewFeatures;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using MrWho.Services.Mediator;
using MrWho.Shared.Models;

namespace MrWho.Endpoints.Auth;

public sealed class RegisterGetHandler : IRequestHandler<RegisterGetRequest, IActionResult>
{
    private readonly IConfiguration _configuration;
    private readonly IHostEnvironment _env;

    public RegisterGetHandler(IConfiguration configuration, IHostEnvironment env)
    {
        _configuration = configuration;
        _env = env;
    }

    public Task<IActionResult> Handle(RegisterGetRequest request, CancellationToken cancellationToken)
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
        return Task.FromResult<IActionResult>(new ViewResult { ViewName = "Register", ViewData = new ViewDataDictionary(vd) { Model = new RegisterUserRequest() } });
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
