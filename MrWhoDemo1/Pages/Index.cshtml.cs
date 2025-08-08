using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace MrWhoDemo1.Pages;

// CRITICAL FIX: Remove [Authorize] to prevent automatic re-authentication after logout
// The page will show different content based on authentication status
public class IndexModel : PageModel
{
    private readonly ILogger<IndexModel> _logger;

    public bool ShowLogoutSuccess { get; set; }

    public IndexModel(ILogger<IndexModel> logger)
    {
        _logger = logger;
    }

    public void OnGet()
    {
        var userName = User.Identity?.Name ?? "Anonymous";
        var isAuthenticated = User.Identity?.IsAuthenticated == true;
        
        // Check if user just logged out successfully
        ShowLogoutSuccess = Request.Query.ContainsKey("logout") && 
                           Request.Query["logout"] == "success" && 
                           !isAuthenticated;
        
        if (ShowLogoutSuccess)
        {
            _logger.LogInformation("? Logout success page displayed - user successfully logged out");
        }
        else
        {
            _logger.LogInformation("Home page accessed by user: {UserName} (Authenticated: {IsAuthenticated})", 
                userName, isAuthenticated);
        }
    }
}
