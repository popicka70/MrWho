using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace MrWhoDemo1.Pages;

[Authorize]
public class SecureModel : PageModel
{
    private readonly ILogger<SecureModel> _logger;

    public SecureModel(ILogger<SecureModel> logger)
    {
        _logger = logger;
    }

    public void OnGet()
    {
        _logger.LogInformation("Secure page accessed by user: {UserName}", User.Identity?.Name ?? "Anonymous");
    }
}
