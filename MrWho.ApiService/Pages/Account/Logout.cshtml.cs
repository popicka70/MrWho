using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using MrWho.ApiService.Models;

namespace MrWho.ApiService.Pages.Account;

public class LogoutModel : PageModel
{
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly ILogger<LogoutModel> _logger;

    public LogoutModel(SignInManager<ApplicationUser> signInManager, ILogger<LogoutModel> logger)
    {
        _signInManager = signInManager;
        _logger = logger;
    }

    public string? PostLogoutRedirectUri { get; set; }

    public async Task<IActionResult> OnGet(string? returnUrl = null)
    {
        await _signInManager.SignOutAsync();
        _logger.LogInformation("User logged out.");

        PostLogoutRedirectUri = returnUrl;
        
        return Page();
    }

    public async Task<IActionResult> OnPost(string? returnUrl = null)
    {
        await _signInManager.SignOutAsync();
        _logger.LogInformation("User logged out.");

        if (returnUrl != null)
        {
            return LocalRedirect(returnUrl);
        }
        else
        {
            return RedirectToPage();
        }
    }
}