using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace MrWhoDemo1.Pages.Account;

public class LogoutModel : PageModel
{
    private readonly ILogger<LogoutModel> _logger;
    private const string Demo1CookieScheme = "Demo1Cookies"; // Match the scheme from Program.cs

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

            // Sign out from the local application first using client-specific scheme
            await HttpContext.SignOutAsync(Demo1CookieScheme);
            _logger.LogDebug("Signed out from Demo1 cookie scheme");

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