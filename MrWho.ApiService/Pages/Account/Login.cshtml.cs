using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using MrWho.ApiService.Models;
using System.ComponentModel.DataAnnotations;

namespace MrWho.ApiService.Pages.Account;

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

    public async Task<IActionResult> OnGetAsync(string? returnUrl = null)
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

        // Check if user is already authenticated
        if (_signInManager.IsSignedIn(User))
        {
            _logger.LogInformation("User is already authenticated, redirecting to: {ReturnUrl}", returnUrl);

            // If the user is already authenticated and this is an OIDC authorization request,
            // redirect them back to complete the authorization flow
            if (returnUrl.Contains("/connect/authorize"))
            {
                _logger.LogInformation("Redirecting authenticated user to OIDC authorization endpoint");
                return LocalRedirect(returnUrl);
            }

            // For non-OIDC requests, redirect to the return URL or home
            return LocalRedirect(returnUrl);
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

        // Return the page for unauthenticated users
        return Page();
    }

    public async Task<IActionResult> OnPostAsync(string? returnUrl = null)
    {
        if (string.IsNullOrEmpty(returnUrl))
        {
            returnUrl = Url.Content("~/");
        }

        _logger.LogInformation("Login POST attempt - ReturnUrl length: {Length}", returnUrl?.Length ?? 0);
        
        // Log request details for debugging
        _logger.LogInformation("Request Method: {Method}", Request.Method);
        _logger.LogInformation("Request ContentType: {ContentType}", Request.ContentType ?? "null");
        _logger.LogInformation("Request ContentLength: {ContentLength}", Request.ContentLength ?? 0);
        _logger.LogInformation("Request HasFormContentType: {HasFormContentType}", Request.HasFormContentType);
        
        // Try to access the form and log any errors
        try
        {
            var formCount = Request.Form.Count;
            _logger.LogInformation("Form collection count: {Count}", formCount);
            
            if (formCount > 0)
            {
                _logger.LogInformation("Form data received:");
                foreach (var item in Request.Form)
                {
                    _logger.LogInformation("  {Key}: {Value}", item.Key,
                        item.Key.Contains("password", StringComparison.OrdinalIgnoreCase) ? "[HIDDEN]" : item.Value.ToString());
                }
            }
            else
            {
                _logger.LogWarning("Form collection is empty!");
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error accessing Request.Form");
        }
        
        _logger.LogInformation("Input.Email: '{Email}', Input.Password length: {PasswordLength}",
            Input.Email ?? "null", Input.Password?.Length ?? 0);
        _logger.LogInformation("ModelState.IsValid: {IsValid}", ModelState.IsValid);
        _logger.LogInformation("ModelState.ErrorCount: {ErrorCount}", ModelState.ErrorCount);

        // Log model binding details
        _logger.LogInformation("Model binding details:");
        _logger.LogInformation("  Input object is null: {IsNull}", Input == null);
        if (Input != null)
        {
            _logger.LogInformation("  Input.Email is null or empty: {IsNullOrEmpty}", string.IsNullOrEmpty(Input.Email));
            _logger.LogInformation("  Input.Password is null or empty: {IsNullOrEmpty}", string.IsNullOrEmpty(Input.Password));
            _logger.LogInformation("  Input.RememberMe value: {RememberMe}", Input.RememberMe);
        }

        // Log specific validation errors
        if (!ModelState.IsValid)
        {
            _logger.LogWarning("ModelState validation failed:");
            foreach (var key in ModelState.Keys)
            {
                var state = ModelState[key];
                if (state?.Errors.Count > 0)
                {
                    foreach (var error in state.Errors)
                    {
                        _logger.LogWarning("  Field '{Field}': {Error}", key, error.ErrorMessage);
                    }
                }
            }
            return Page();
        }

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

            // For OIDC flow, redirect back to the authorization endpoint to complete the flow
            if (returnUrl.Contains("/connect/authorize"))
            {
                _logger.LogInformation("Redirecting to OIDC authorization endpoint: {ReturnUrl}", returnUrl);
                return LocalRedirect(returnUrl);
            }

            // For non-OIDC requests, redirect to the return URL or home
            _logger.LogInformation("Redirecting to return URL: {ReturnUrl}", returnUrl);
            return LocalRedirect(returnUrl);
        }

        if (result.RequiresTwoFactor)
        {
            _logger.LogInformation("Two-factor authentication required for: {Email}", Input.Email);
            return RedirectToPage("./LoginWith2fa", new { ReturnUrl = returnUrl, RememberMe = Input.RememberMe });
        }

        if (result.IsLockedOut)
        {
            _logger.LogWarning("User account locked out: {Email}", Input.Email);
            return RedirectToPage("./Lockout");
        }

        // Login failed - invalid credentials
        _logger.LogWarning("Login failed: Invalid credentials for email: {Email}", Input.Email);
        ModelState.AddModelError(string.Empty, "Invalid login attempt.");
        return Page();
    }
}