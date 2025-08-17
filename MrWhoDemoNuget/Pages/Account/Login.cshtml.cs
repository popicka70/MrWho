using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace MrWhoDemoNuget.Pages.Account;

public class LoginModel : PageModel
{
    public IActionResult OnGet()
    {
        // Use default challenge scheme configured by MrWho.ClientAuth (MrWho.{ClientId}.OIDC)
        return Challenge(new AuthenticationProperties { RedirectUri = Url.Content("~/") });
    }
}
