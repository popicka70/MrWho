using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using MrWho.Services;
using System.Security.Claims;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace MrWho.Controllers;

[Route("connect")]
public class AuthController : Controller
{
    private readonly SignInManager<IdentityUser> _signInManager;
    private readonly UserManager<IdentityUser> _userManager;
    private readonly IClientCookieConfigurationService _cookieService;
    private readonly ILogger<AuthController> _logger;

    public AuthController(
        SignInManager<IdentityUser> signInManager, 
        UserManager<IdentityUser> userManager,
        IClientCookieConfigurationService cookieService,
        ILogger<AuthController> logger)
    {
        _signInManager = signInManager;
        _userManager = userManager;
        _cookieService = cookieService;
        _logger = logger;
    }

    // REMOVED: [HttpGet("authorize")] - Now handled by minimal API with client-specific cookies

    [HttpGet("login")]
    public IActionResult Login(string? returnUrl = null, string? clientId = null)
    {
        _logger.LogDebug("Login page requested, returnUrl = {ReturnUrl}, clientId = {ClientId}", returnUrl, clientId);
        ViewData["ReturnUrl"] = returnUrl;
        ViewData["ClientId"] = clientId;
        return View(new LoginViewModel());
    }

    [HttpPost("login")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Login(LoginViewModel model, string? returnUrl = null, string? clientId = null)
    {
        ViewData["ReturnUrl"] = returnUrl;
        ViewData["ClientId"] = clientId;
        _logger.LogDebug("Login POST: Email={Email}, ReturnUrl={ReturnUrl}, ClientId={ClientId}", 
            model.Email, returnUrl, clientId);

        if (ModelState.IsValid)
        {
            var result = await _signInManager.PasswordSignInAsync(model.Email, model.Password, model.RememberMe, lockoutOnFailure: false);
            _logger.LogDebug("Login attempt result: Success={Success}", result.Succeeded);
            
            if (result.Succeeded)
            {
                // If we have a client ID, also sign in with the client-specific scheme
                if (!string.IsNullOrEmpty(clientId))
                {
                    try
                    {
                        var user = await _userManager.FindByNameAsync(model.Email);
                        if (user != null)
                        {
                            var cookieScheme = _cookieService.GetCookieSchemeForClient(clientId);
                            
                            // Create claims identity for client-specific cookie
                            var identity = new ClaimsIdentity(cookieScheme);
                            identity.AddClaim(Claims.Subject, user.Id);
                            identity.AddClaim(Claims.Email, user.Email!);
                            identity.AddClaim(Claims.Name, user.UserName!);
                            identity.AddClaim(Claims.PreferredUsername, user.UserName!);

                            // Add roles
                            var roles = await _userManager.GetRolesAsync(user);
                            foreach (var role in roles)
                            {
                                identity.AddClaim(Claims.Role, role);
                            }

                            var principal = new ClaimsPrincipal(identity);
                            await HttpContext.SignInAsync(cookieScheme, principal);
                            
                            _logger.LogDebug("Signed in user {UserName} with client-specific scheme {Scheme}", 
                                user.UserName, cookieScheme);
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning(ex, "Failed to sign in with client-specific scheme for client {ClientId}", clientId);
                        // Continue anyway - the default SignInManager login above should still work
                    }
                }

                if (!string.IsNullOrEmpty(returnUrl) && Url.IsLocalUrl(returnUrl))
                {
                    _logger.LogDebug("Login successful, redirecting to: {ReturnUrl}", returnUrl);
                    return Redirect(returnUrl);
                }
                _logger.LogDebug("Login successful, redirecting to Home");
                return RedirectToAction("Index", "Home");
            }
            else
            {
                _logger.LogDebug("Login failed: {Result}", result);
                ModelState.AddModelError(string.Empty, "Invalid login attempt.");
            }
        }
        else
        {
            _logger.LogDebug("Login ModelState invalid");
        }

        return View(model);
    }

    [HttpGet("logout")]
    public async Task<IActionResult> Logout(string? clientId = null)
    {
        var request = HttpContext.GetOpenIddictServerRequest();
        
        // If we have a client ID, sign out from the client-specific scheme
        if (!string.IsNullOrEmpty(clientId))
        {
            try
            {
                var cookieScheme = _cookieService.GetCookieSchemeForClient(clientId);
                await HttpContext.SignOutAsync(cookieScheme);
                _logger.LogDebug("Signed out from client-specific scheme {Scheme} for client {ClientId}", 
                    cookieScheme, clientId);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to sign out from client-specific scheme for client {ClientId}", clientId);
            }
        }
        
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
    public async Task<IActionResult> LogoutPost(string? clientId = null)
    {
        // If we have a client ID, sign out from the client-specific scheme
        if (!string.IsNullOrEmpty(clientId))
        {
            try
            {
                var cookieScheme = _cookieService.GetCookieSchemeForClient(clientId);
                await HttpContext.SignOutAsync(cookieScheme);
                _logger.LogDebug("Signed out from client-specific scheme {Scheme} for client {ClientId}", 
                    cookieScheme, clientId);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to sign out from client-specific scheme for client {ClientId}", clientId);
            }
        }

        await _signInManager.SignOutAsync();
        return RedirectToAction("Index", "Home");
    }
}

public class LoginViewModel
{
    public string Email { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;
    public bool RememberMe { get; set; }
}