using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace MrWhoDemoNuget.Pages.Account;

public class LoginModel : PageModel
{
    public IActionResult OnGet()
    {
        return new ChallengeResult(OpenIdConnectDefaults.AuthenticationScheme,
            new AuthenticationProperties { RedirectUri = Url.Content("~/") });
    }
}
