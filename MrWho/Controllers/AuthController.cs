using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using MrWho.Services;
using System.Security.Claims;
using System.Web;
using static OpenIddict.Abstractions.OpenIddictConstants;
using MrWho.Shared.Models;
using MrWho.Data;
using MrWho.Models;
using Microsoft.AspNetCore.RateLimiting;
using MrWho.Services.Mediator; // added
using MrWho.Endpoints.Auth; // added

namespace MrWho.Controllers;

[Route("connect")]
public class AuthController : Controller
{
    private readonly IMediator _mediator;
    private readonly IReturnUrlStore _returnUrlStore;

    public AuthController(IMediator mediator, IReturnUrlStore returnUrlStore)
    {
        _mediator = mediator;
        _returnUrlStore = returnUrlStore;
    }

    [HttpGet("login")]
    [EnableRateLimiting("rl.login")]
    public async Task<IActionResult> Login(string? returnUrl = null, string? clientId = null, string? mode = null)
    {
        // If using PAR (request_uri present) or the URL is long, store and redirect to short form to keep address bar clean.
        if (!string.IsNullOrEmpty(returnUrl) &&
            (returnUrl.Contains("request_uri=", StringComparison.OrdinalIgnoreCase) || returnUrl.Length > 256))
        {
            var id = await _returnUrlStore.SaveAsync(returnUrl, clientId, TimeSpan.FromMinutes(10));
            return Redirect($"/connect/login-short?id={Uri.EscapeDataString(id)}&clientId={Uri.EscapeDataString(clientId ?? string.Empty)}");
        }
        return await _mediator.Send(new LoginGetRequest(HttpContext, returnUrl, clientId, mode));
    }

    [HttpGet("login-short")]
    [EnableRateLimiting("rl.login")]
    public async Task<IActionResult> LoginShort(string id, string? clientId = null, string? mode = null)
    {
        var resolved = await _returnUrlStore.ResolveAsync(id);
        if (string.IsNullOrEmpty(resolved))
        {
            // Fallback to normal login without a returnUrl
            return await _mediator.Send(new LoginGetRequest(HttpContext, null, clientId, mode));
        }
        return await _mediator.Send(new LoginGetRequest(HttpContext, resolved, clientId, mode));
    }

    [HttpPost("login-short")]
    [ValidateAntiForgeryToken]
    [EnableRateLimiting("rl.login")]
    public async Task<IActionResult> LoginShortPost(string id, [FromForm] LoginViewModel model, string? clientId = null)
    {
        var resolved = await _returnUrlStore.ResolveAsync(id);
        return await _mediator.Send(new LoginPostRequest(HttpContext, model, resolved, clientId));
    }

    [HttpPost("login")]
    [ValidateAntiForgeryToken]
    [EnableRateLimiting("rl.login")] // limit login attempts
    public async Task<IActionResult> Login(LoginViewModel model, string? returnUrl = null, string? clientId = null)
        => await _mediator.Send(new LoginPostRequest(HttpContext, model, returnUrl, clientId));

    [HttpGet("logout")]
    public async Task<IActionResult> Logout(string? clientId = null, string? post_logout_redirect_uri = null)
        => await _mediator.Send(new LogoutGetRequest(HttpContext, clientId, post_logout_redirect_uri));

    [HttpPost("logout")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> LogoutPost(string? clientId = null, string? post_logout_redirect_uri = null)
        => await _mediator.Send(new LogoutPostRequest(HttpContext, clientId, post_logout_redirect_uri));

    [HttpGet("access-denied")]
    public async Task<IActionResult> AccessDenied(string? returnUrl = null, string? clientId = null)
        => await _mediator.Send(new AccessDeniedGetRequest(HttpContext, returnUrl, clientId));

    [HttpGet("register")]
    [AllowAnonymous]
    [EnableRateLimiting("rl.register")] // limit registration page fetches
    public async Task<IActionResult> Register()
        => await _mediator.Send(new RegisterGetRequest(HttpContext));

    [HttpPost("register")]
    [AllowAnonymous]
    [ValidateAntiForgeryToken]
    [EnableRateLimiting("rl.register")] // limit registration attempts
    public async Task<IActionResult> Register([FromForm] RegisterUserRequest input)
        => await _mediator.Send(new RegisterPostRequest(HttpContext, input));

    [HttpGet("register/success")]
    [AllowAnonymous]
    public async Task<IActionResult> RegisterSuccess([FromQuery] string? returnUrl = null, [FromQuery] string? clientId = null)
        => await _mediator.Send(new MrWho.Endpoints.Auth.RegisterSuccessGetRequest(HttpContext));

    [HttpGet("userinfo")]
    [HttpPost("userinfo")]
    [Authorize]
    public async Task<IActionResult> Userinfo()
    {
        // This will trigger the OpenIddict pipeline including your handler
        var request = HttpContext.GetOpenIddictServerRequest();
        var result = await HttpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);

        // The handler should process this
        return Ok(); // OpenIddict will handle the actual response
    }
}

public class LoginViewModel
{
    public string Email { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;
    public bool RememberMe { get; set; }
    public bool UseCode { get; set; }
    public string? Code { get; set; }
}