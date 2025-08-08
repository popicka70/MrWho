using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace MrWhoDemo1.Pages.Account;

public class LogoutModel : PageModel
{
    private readonly ILogger<LogoutModel> _logger;

    public LogoutModel(ILogger<LogoutModel> logger)
    {
        _logger = logger;
    }

    public IActionResult OnGet()
    {
        if (User.Identity?.IsAuthenticated != true)
        {
            return LocalRedirect("/");
        }

        return Page();
    }

    public async Task<IActionResult> OnPost()
    {
        if (User.Identity?.IsAuthenticated == true)
        {
            _logger.LogDebug("Starting logout process for Demo1 application");

            // Sign out from the local application first
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            _logger.LogDebug("Signed out from local cookie scheme");

            // Complete the OIDC logout flow with the provider
            // The MrWho server will now automatically detect the client and clean up all schemes
            return SignOut(new AuthenticationProperties
            {
                RedirectUri = "/"
            }, OpenIdConnectDefaults.AuthenticationScheme);
        }

        return LocalRedirect("/");
    }
}