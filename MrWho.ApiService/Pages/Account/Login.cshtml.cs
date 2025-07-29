using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using MrWho.ApiService.Models;
using System.ComponentModel.DataAnnotations;

namespace MrWho.ApiService.Pages.Account;

[IgnoreAntiforgeryToken]
public class LoginModel : PageModel
{
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly ILogger<LoginModel> _logger;

    public LoginModel(
        SignInManager<ApplicationUser> signInManager,
        UserManager<ApplicationUser> userManager,
        ILogger<LoginModel> logger)
    {
        _signInManager = signInManager;
        _userManager = userManager;
        _logger = logger;
    }

    [BindProperty]
    public InputModel Input { get; set; } = new();

    public string? ReturnUrl { get; set; }

    public string? ErrorMessage { get; set; }

    public class InputModel
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; } = string.Empty;

        [Required]
        [DataType(DataType.Password)]
        public string Password { get; set; } = string.Empty;

        [Display(Name = "Remember me?")]
        public bool RememberMe { get; set; }
    }

    public async Task OnGetAsync(string? returnUrl = null)
    {
        if (!string.IsNullOrEmpty(ErrorMessage))
        {
            ModelState.AddModelError(string.Empty, ErrorMessage);
        }

        // Handle OIDC authorization requests properly
        if (string.IsNullOrEmpty(returnUrl))
        {
            returnUrl = Url.Content("~/");
        }

        // Clear the existing external cookie to ensure a clean login process
        try
        {
            await HttpContext.SignOutAsync(IdentityConstants.ExternalScheme);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to sign out external scheme, continuing anyway");
        }

        ReturnUrl = returnUrl;
        
        _logger.LogInformation("Login page accessed with ReturnUrl length: {Length}, starts with: {StartsWith}", 
            returnUrl?.Length ?? 0, 
            returnUrl?.Length > 0 ? returnUrl.Substring(0, Math.Min(100, returnUrl.Length)) : "null");
    }

    public async Task<IActionResult> OnPostAsync(string? returnUrl = null)
    {
        if (string.IsNullOrEmpty(returnUrl))
        {
            returnUrl = Url.Content("~/");
        }

        _logger.LogInformation("Login attempt for email: {Email}, ReturnUrl length: {Length}", 
            Input.Email, returnUrl?.Length ?? 0);

        if (ModelState.IsValid)
        {
            var user = await _userManager.FindByEmailAsync(Input.Email);
            if (user == null)
            {
                _logger.LogWarning("Login failed: User not found for email: {Email}", Input.Email);
                ModelState.AddModelError(string.Empty, "Invalid login attempt.");
                return Page();
            }

            if (!user.IsActive)
            {
                _logger.LogWarning("Login failed: Account not active for email: {Email}", Input.Email);
                ModelState.AddModelError(string.Empty, "Account is not active.");
                return Page();
            }

            var result = await _signInManager.PasswordSignInAsync(
                user, Input.Password, Input.RememberMe, lockoutOnFailure: false);

            if (result.Succeeded)
            {
                _logger.LogInformation("User logged in successfully: {Email}", Input.Email);
                
                // For OIDC flow, redirect back to the authorization endpoint
                if (returnUrl.Contains("/connect/authorize"))
                {
                    _logger.LogInformation("Redirecting to OIDC authorization endpoint");
                    return LocalRedirect(returnUrl);
                }
                
                return LocalRedirect(returnUrl);
            }
            
            if (result.RequiresTwoFactor)
            {
                return RedirectToPage("./LoginWith2fa", new { ReturnUrl = returnUrl, RememberMe = Input.RememberMe });
            }
            
            if (result.IsLockedOut)
            {
                _logger.LogWarning("User account locked out: {Email}", Input.Email);
                return RedirectToPage("./Lockout");
            }
            else
            {
                _logger.LogWarning("Login failed: Invalid credentials for email: {Email}", Input.Email);
                ModelState.AddModelError(string.Empty, "Invalid login attempt.");
                return Page();
            }
        }

        // If we got this far, something failed, redisplay form
        foreach (var modelError in ModelState.Values.SelectMany(v => v.Errors))
        {
            _logger.LogWarning("Model validation error: {Error}", modelError.ErrorMessage);
        }
        return Page();
    }
}