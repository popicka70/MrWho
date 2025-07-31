using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using System.Security.Claims;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace MrWho.Controllers;

[Route("connect")]
public class AuthController : Controller
{
    private readonly SignInManager<IdentityUser> _signInManager;
    private readonly UserManager<IdentityUser> _userManager;

    public AuthController(SignInManager<IdentityUser> signInManager, UserManager<IdentityUser> userManager)
    {
        _signInManager = signInManager;
        _userManager = userManager;
    }

    [HttpGet("authorize")]
    public async Task<IActionResult> Authorize()
    {
        var request = HttpContext.GetOpenIddictServerRequest() ??
                      throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

        // Log the request for debugging
        Console.WriteLine($"Authorization request received: ClientId={request.ClientId}, ResponseType={request.ResponseType}, RedirectUri={request.RedirectUri}");
        Console.WriteLine($"User authenticated: {User.Identity?.IsAuthenticated == true}");

        // If the user is already authenticated, process the authorization request
        if (User.Identity?.IsAuthenticated == true)
        {
            Console.WriteLine($"User is authenticated, processing authorization");
            return await ProcessAuthorizationAsync(request);
        }

        Console.WriteLine($"User not authenticated, redirecting to login");

        // Store the authorization request in TempData to preserve it across redirects
        TempData["AuthorizationRequest"] = request.ToString();

        // Preserve query parameters when redirecting to login
        var returnUrl = Url.Action(nameof(Authorize)) + HttpContext.Request.QueryString;
        return RedirectToAction(nameof(Login), new { returnUrl });
    }

    [HttpGet("login")]
    public IActionResult Login(string? returnUrl = null)
    {
        Console.WriteLine($"Login page requested, returnUrl = {returnUrl}");
        ViewData["ReturnUrl"] = returnUrl;
        return View(new LoginViewModel());
    }

    [HttpPost("login")]
    //[ValidateAntiForgeryToken]
    public async Task<IActionResult> Login(LoginViewModel model, string? returnUrl = null)
    {
        ViewData["ReturnUrl"] = returnUrl;
        Console.WriteLine($"Login POST: Email={model.Email}, ReturnUrl={returnUrl}");

        if (ModelState.IsValid)
        {
            var result = await _signInManager.PasswordSignInAsync(model.Email, model.Password, model.RememberMe, lockoutOnFailure: false);
            Console.WriteLine($"Login attempt result: Success={result.Succeeded}");
            
            if (result.Succeeded)
            {
                if (!string.IsNullOrEmpty(returnUrl) && Url.IsLocalUrl(returnUrl))
                {
                    Console.WriteLine($"Login successful, redirecting to: {returnUrl}");
                    return Redirect(returnUrl);
                }
                Console.WriteLine($"Login successful, redirecting to Home");
                return RedirectToAction("Index", "Home");
            }
            else
            {
                Console.WriteLine($"Login failed: {result}");
                ModelState.AddModelError(string.Empty, "Invalid login attempt.");
            }
        }
        else
        {
            Console.WriteLine($"Login ModelState invalid");
        }

        return View(model);
    }

    [HttpGet("logout")]
    public async Task<IActionResult> Logout()
    {
        var request = HttpContext.GetOpenIddictServerRequest();
        
        if (request != null)
        {
            // This is an OIDC logout request
            await _signInManager.SignOutAsync();
            
            // Return a SignOut result to complete the OIDC logout flow
            return SignOut(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        // Regular logout
        await _signInManager.SignOutAsync();
        return RedirectToAction("Index", "Home");
    }

    [HttpPost("logout")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> LogoutPost()
    {
        await _signInManager.SignOutAsync();
        return RedirectToAction("Index", "Home");
    }

    private async Task<IActionResult> ProcessAuthorizationAsync(OpenIddictRequest request)
    {
        Console.WriteLine($"ProcessAuthorizationAsync called");
        
        var user = await _userManager.GetUserAsync(User);
        Console.WriteLine($"User lookup result: Found={user != null}, Id={user?.Id}, UserName={user?.UserName}");
        
        if (user == null)
        {
            Console.WriteLine($"No user found via GetUserAsync - Identity claim configuration may be incorrect");
            Console.WriteLine($"Available claims: {string.Join(", ", User.Claims.Select(c => $"{c.Type}={c.Value}"))}");
            return Forbid(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        try
        {
            // Create a new ClaimsIdentity containing the claims that
            // will be used to create an id_token, a token or a code.
            var identity = new ClaimsIdentity(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
            identity.AddClaim(Claims.Subject, user.Id);
            identity.AddClaim(Claims.Email, user.Email!);
            identity.AddClaim(Claims.Name, user.UserName!);
            identity.AddClaim(Claims.PreferredUsername, user.UserName!);

            Console.WriteLine($"Created identity with claims: Subject={user.Id}, Email={user.Email}, Name={user.UserName}");

            // Set the list of scopes granted to the client application.
            var principal = new ClaimsPrincipal(identity);
            principal.SetScopes(request.GetScopes());

            Console.WriteLine($"Set scopes: {string.Join(", ", request.GetScopes())}");
            Console.WriteLine($"Returning SignIn result");

            // Automatically consent to the authorization request
            return SignIn(principal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error in ProcessAuthorizationAsync: {ex}");
            return Forbid(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }
    }
}

public class LoginViewModel
{
    public string Email { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;
    public bool RememberMe { get; set; }
}