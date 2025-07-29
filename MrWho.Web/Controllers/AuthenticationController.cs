using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;

namespace MrWho.Web.Controllers;

[Route("account")]
public class AuthenticationController : Controller
{
    private readonly ILogger<AuthenticationController> _logger;

    public AuthenticationController(ILogger<AuthenticationController> logger)
    {
        _logger = logger;
    }

    [HttpGet("challenge")]
    public IActionResult Challenge(string? returnUrl = null)
    {
        _logger.LogInformation("Starting OpenID Connect challenge. ReturnUrl: {ReturnUrl}", returnUrl);
        
        var properties = new AuthenticationProperties();
        if (!string.IsNullOrEmpty(returnUrl))
        {
            properties.RedirectUri = returnUrl;
        }

        return Challenge(properties, OpenIdConnectDefaults.AuthenticationScheme);
    }

    [HttpGet("signout")]
    public new IActionResult SignOut()
    {
        _logger.LogInformation("Starting OpenID Connect signout");
        
        var properties = new AuthenticationProperties
        {
            RedirectUri = "/"
        };

        return SignOut(properties, 
            OpenIdConnectDefaults.AuthenticationScheme,
            CookieAuthenticationDefaults.AuthenticationScheme);
    }

    [HttpGet("error")]
    public IActionResult Error(string? message = null)
    {
        ViewBag.ErrorMessage = message ?? "An authentication error occurred.";
        return View();
    }
}