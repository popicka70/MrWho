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

    public AuthController(IMediator mediator)
    {
        _mediator = mediator; // added
    }

    [HttpGet("login")]
    [EnableRateLimiting("rl.login")] // limit login page fetches
    public async Task<IActionResult> Login(string? returnUrl = null, string? clientId = null, string? mode = null)
        => await _mediator.Send(new LoginGetRequest(HttpContext, returnUrl, clientId, mode));

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
    public async Task<IActionResult> RegisterSuccess()
        => await _mediator.Send(new RegisterSuccessGetRequest());
}

public class LoginViewModel
{
    public string Email { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;
    public bool RememberMe { get; set; }
    public bool UseCode { get; set; }
    public string? Code { get; set; }
}