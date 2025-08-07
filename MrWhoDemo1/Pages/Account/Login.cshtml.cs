using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace MrWhoDemo1.Pages.Account;

public class LoginModel : PageModel
{
    public IActionResult OnGet(string? returnUrl = null)
    {
        if (User.Identity?.IsAuthenticated == true)
        {
            return LocalRedirect(returnUrl ?? "/");
        }

        return Page();
    }

    public IActionResult OnPost(string? returnUrl = null)
    {
        var authenticationProperties = new AuthenticationProperties
        {
            RedirectUri = returnUrl ?? "/"
        };

        return Challenge(authenticationProperties, OpenIdConnectDefaults.AuthenticationScheme);
    }
}