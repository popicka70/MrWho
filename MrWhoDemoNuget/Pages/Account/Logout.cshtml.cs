using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace MrWhoDemoNuget.Pages.Account;

public class LogoutModel : PageModel
{
    public async Task<IActionResult> OnGet()
    {
        // Only sign out the default cookie; the OIDC handler will use the default challenge scheme
        await HttpContext.SignOutAsync();
        return LocalRedirect("~/");
    }
}
