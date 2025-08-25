using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;

namespace MrWho.Services;

public interface ILogoutHelper
{
    Task SignOutAsync(HttpContext http);
}

public sealed class LogoutHelper : ILogoutHelper
{
    private readonly ILogger<LogoutHelper> _logger;
    private readonly IConfiguration _configuration;
    private readonly SignInManager<IdentityUser> _signInManager;

    public LogoutHelper(ILogger<LogoutHelper> logger, IConfiguration configuration, SignInManager<IdentityUser> signInManager)
    {
        _logger = logger; _configuration = configuration; _signInManager = signInManager;
    }

    public async Task SignOutAsync(HttpContext http)
    {
        try
        {
            await _signInManager.SignOutAsync();
            DeleteCookie(http, ".AspNetCore.Identity.Application");
            _logger.LogInformation("User signed out (single cookie mode)");
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Error during sign-out");
        }
    }

    private void DeleteCookie(HttpContext http, string cookieName)
    {
        if (string.IsNullOrWhiteSpace(cookieName)) return;
        var secure = http.Request.IsHttps;
        http.Response.Cookies.Delete(cookieName, new CookieOptions
        {
            Path = "/",
            HttpOnly = true,
            Secure = secure,
            SameSite = SameSiteMode.None
        });
    }
}
