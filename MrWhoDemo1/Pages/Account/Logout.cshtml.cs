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

            try
            {
                // CRITICAL FIX: Use the proper SignOut approach for OpenID Connect
                // This will:
                // 1. Sign out from local cookies
                // 2. Redirect to the OIDC provider's end session endpoint
                // 3. Have the provider redirect back to our post-logout redirect URI
                
                var properties = new AuthenticationProperties
                {
                    RedirectUri = "/" // Where to go after the OIDC logout is complete
                };

                _logger.LogDebug("Initiating complete OIDC logout flow");

                // This single call will handle both local and remote logout
                return SignOut(properties, OpenIdConnectDefaults.AuthenticationScheme, Demo1CookieScheme);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during logout process");
                
                // Fallback: at least clear local authentication
                await HttpContext.SignOutAsync(Demo1CookieScheme);
                return LocalRedirect("/");
            }
        }

        return LocalRedirect("/");
    }
}