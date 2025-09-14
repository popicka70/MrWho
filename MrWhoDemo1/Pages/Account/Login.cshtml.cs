using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace MrWhoDemo1.Pages.Account;

public class LoginModel : PageModel
{
    private readonly ILogger<LoginModel> _logger;

    public string? ReturnUrl { get; set; }
    public bool ShowDirectLogin { get; set; }

    public LoginModel(ILogger<LoginModel> logger)
    {
        _logger = logger;
    }

    public IActionResult OnGet(string? returnUrl = null, bool direct = false)
    {
        if (User.Identity?.IsAuthenticated == true)
        {
            return LocalRedirect(returnUrl ?? "/");
        }

        ReturnUrl = returnUrl;
        ShowDirectLogin = direct;

        // If direct=true, immediately redirect to OIDC server
        // This is for the "Login with MrWho" button on the home page
        if (direct)
        {
            return OnPostChallenge(returnUrl);
        }

        return Page();
    }

    /// <summary>
    /// Initiate OIDC authentication challenge - redirects to MrWho Identity Server
    /// </summary>
    public IActionResult OnPostChallenge(string? returnUrl = null)
    {
        var authenticationProperties = new AuthenticationProperties
        {
            RedirectUri = returnUrl ?? "/"
        };

        _logger.LogInformation("?? Initiating OIDC authentication challenge for Demo1 client");
        _logger.LogInformation("   - Client ID: mrwho_demo1");
        _logger.LogInformation("   - Return URL: {ReturnUrl}", returnUrl ?? "/");
        _logger.LogInformation("   - Will redirect to: https://localhost:7113/connect/authorize");

        return Challenge(authenticationProperties, OpenIdConnectDefaults.AuthenticationScheme);
    }
}
