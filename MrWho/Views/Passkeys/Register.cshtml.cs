using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace MrWho.Views.Passkeys;

[Authorize]
public class RegisterModel : PageModel
{
    public void OnGet()
    {
    }
}
