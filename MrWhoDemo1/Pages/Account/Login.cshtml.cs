using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.ComponentModel.DataAnnotations;

namespace MrWhoDemo1.Pages.Account;

public class LoginModel : PageModel
{
    private readonly ILogger<LoginModel> _logger;

    [BindProperty]
    public LoginInputModel Input { get; set; } = new();

    public string? ReturnUrl { get; set; }

    public LoginModel(ILogger<LoginModel> logger)
    {
        _logger = logger;
    }

    public IActionResult OnGet(string? returnUrl = null)
    {
        if (User.Identity?.IsAuthenticated == true)
        {
            return LocalRedirect(returnUrl ?? "/");
        }

        ReturnUrl = returnUrl;
        return Page();
    }

    public IActionResult OnPost(string? returnUrl = null)
    {
        ReturnUrl = returnUrl;

        // For demo purposes, we'll redirect to the OIDC server regardless of form input
        // The actual authentication will happen at the identity server
        var authenticationProperties = new AuthenticationProperties
        {
            RedirectUri = returnUrl ?? "/"
        };

        _logger.LogInformation("Login form submitted with username: {Username}", Input.Username);
        return Challenge(authenticationProperties, OpenIdConnectDefaults.AuthenticationScheme);
    }
}

public class LoginInputModel
{
    [Required]
    [Display(Name = "Username")]
    public string Username { get; set; } = string.Empty;

    [Required]
    [DataType(DataType.Password)]
    [Display(Name = "Password")]
    public string Password { get; set; } = string.Empty;

    [Display(Name = "Remember me")]
    public bool RememberMe { get; set; }
}