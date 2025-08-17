using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace MrWhoDemoNuget.Pages.Account;

public class LogoutModel : PageModel
{
    public async Task<IActionResult> OnGet()
    {
        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        await HttpContext.SignOutAsync(OpenIdConnectDefaults.AuthenticationScheme, new AuthenticationProperties
        {
            RedirectUri = Url.Content("~/")
        });
        return new EmptyResult();
    }
}
