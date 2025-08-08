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

        // For demo purposes, we'll still redirect to the OIDC server
        // but the form shows what credentials will be used
        var authenticationProperties = new AuthenticationProperties
        {
            RedirectUri = returnUrl ?? "/"
        };

        _logger.LogInformation("Login form submitted with email: {Email}", Input.Email);
        return Challenge(authenticationProperties, OpenIdConnectDefaults.AuthenticationScheme);
    }

    public IActionResult OnPostAutoFill()
    {
        // Auto-fill the demo credentials
        Input.Email = "demo1@example.com";
        Input.Password = "Demo123";
        Input.RememberMe = true;

        _logger.LogDebug("Auto-filled demo credentials");
        
        // Return the page with filled credentials
        ReturnUrl = Request.Form["returnUrl"];
        return Page();
    }
}

public class LoginInputModel
{
    [Required]
    [EmailAddress]
    [Display(Name = "Email")]
    public string Email { get; set; } = string.Empty;

    [Required]
    [DataType(DataType.Password)]
    [Display(Name = "Password")]
    public string Password { get; set; } = string.Empty;

    [Display(Name = "Remember me")]
    public bool RememberMe { get; set; }
}