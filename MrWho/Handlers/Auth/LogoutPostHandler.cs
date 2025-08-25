using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using MrWho.Services;
using MrWho.Services.Mediator;

namespace MrWho.Handlers.Auth;

public sealed class LogoutPostHandler : IRequestHandler<MrWho.Endpoints.Auth.LogoutPostRequest, IActionResult>
{
    private readonly ILogger<LogoutPostHandler> _logger;
    private readonly ILogoutHelper _logoutHelper;

    public LogoutPostHandler(ILogger<LogoutPostHandler> logger, ILogoutHelper logoutHelper)
    { _logger = logger; _logoutHelper = logoutHelper; }

    public async Task<IActionResult> Handle(MrWho.Endpoints.Auth.LogoutPostRequest request, CancellationToken cancellationToken)
    {
        var http = request.HttpContext;
        _logger.LogInformation("POST logout invoked");
        await _logoutHelper.SignOutAsync(http);
        return new RedirectToActionResult("Index", "Home", new { logout = "success" });
    }
}
