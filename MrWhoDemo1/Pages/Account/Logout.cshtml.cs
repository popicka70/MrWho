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
            _logger.LogDebug("Starting logout process for Demo1 application using standard OIDC with server-side session isolation");

            try
            {
                // CORRECTED: Use standard OIDC scheme - server-side DynamicCookieService handles client isolation
                
                var properties = new AuthenticationProperties
                {
                    RedirectUri = "/" // Where to go after the OIDC logout is complete
                };

                _logger.LogDebug("Initiating Demo1 logout using standard OIDC - server-side DynamicCookieService prevents affecting admin app");

                // Use standard OIDC scheme - server-side DynamicCookieService handles client-specific session isolation
                return SignOut(properties, OpenIdConnectDefaults.AuthenticationScheme, Demo1CookieScheme);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during Demo1 logout process");
                
                // Fallback: at least clear local authentication
                await HttpContext.SignOutAsync(Demo1CookieScheme);
                return LocalRedirect("/");
            }
        }

        return LocalRedirect("/");
    }
}