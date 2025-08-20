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

    // Local-only logout: clears the app cookie but keeps the OIDC provider session (SSO preserved)
    public async Task<IActionResult> OnPostAsync()
    {
        if (User.Identity?.IsAuthenticated == true)
        {
            _logger.LogInformation("Demo1 LOCAL-ONLY logout: clearing local cookie only (OIDC provider session remains)");

            try
            {
                await HttpContext.SignOutAsync(Demo1CookieScheme);
                return LocalRedirect("/?logout=success");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during Demo1 local logout process");
                await HttpContext.SignOutAsync(Demo1CookieScheme);
                return LocalRedirect("/?logout=error");
            }
        }

        return LocalRedirect("/");
    }

    // Complete logout: clears local cookie and performs OIDC end-session at the provider
    public IActionResult OnPostComplete()
    {
        if (User.Identity?.IsAuthenticated != true)
        {
            return LocalRedirect("/");
        }

        _logger.LogInformation("Demo1 COMPLETE logout: signing out locally and at OIDC provider");

        var props = new AuthenticationProperties
        {
            // After provider redirects back, OIDC middleware will send the user to options.SignedOutRedirectUri
            RedirectUri = Url.Content("~/")
        };

        // Sign out of both local and OIDC schemes. The OIDC handler will redirect to the identity provider's logout endpoint.
        return SignOut(props, Demo1CookieScheme, OpenIdConnectDefaults.AuthenticationScheme);
    }
}