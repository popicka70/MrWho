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
            _logger.LogInformation("?? Starting Demo1 LOCAL-ONLY logout to avoid affecting other clients");

            try
            {
                // FIXED: Do completely local logout - do NOT hit server's global logout endpoint
                // This prevents interference with other clients' sessions

                _logger.LogInformation("?? Demo1 performing local-only logout: Clearing only local Demo1 session");
                
                // Step 1: Sign out from local Demo1 cookie only (no server call)
                await HttpContext.SignOutAsync(Demo1CookieScheme);
                
                // Step 2: Optional - could call a Demo1-specific logout endpoint if needed
                // But for now, just do local logout to maintain session isolation
                
                _logger.LogInformation("? Demo1 local logout complete: Only Demo1 session cleared, other clients unaffected");
                
                return LocalRedirect("/?logout=success");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "? Error during Demo1 local logout process");
                
                // Fallback: at least clear local authentication
                await HttpContext.SignOutAsync(Demo1CookieScheme);
                return LocalRedirect("/?logout=error");
            }
        }

        return LocalRedirect("/");
    }
}