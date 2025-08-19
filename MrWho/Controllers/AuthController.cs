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
using System.Net.Http;
using System.Text.Json;
using Microsoft.EntityFrameworkCore; // added
using MrWho.Services.Mediator; // added
using MrWho.Endpoints.Auth; // added

namespace MrWho.Controllers;

[Route("connect")]
public class AuthController : Controller
{
    private readonly SignInManager<IdentityUser> _signInManager;
    private readonly UserManager<IdentityUser> _userManager;
    private readonly IClientCookieConfigurationService _cookieService;
    private readonly IDynamicCookieService _dynamicCookieService;
    private readonly IOpenIddictApplicationManager _applicationManager;
    private readonly ApplicationDbContext _db;
    private readonly ILogger<AuthController> _logger;
    private readonly IConfiguration _configuration;
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly IHostEnvironment _env;
    private readonly IMediator _mediator; // added

    public AuthController(
        SignInManager<IdentityUser> signInManager,
        UserManager<IdentityUser> userManager,
        IClientCookieConfigurationService cookieService,
        IDynamicCookieService dynamicCookieService,
        IOpenIddictApplicationManager applicationManager,
        ApplicationDbContext db,
        ILogger<AuthController> logger,
        IConfiguration configuration,
        IHttpClientFactory httpClientFactory,
        IHostEnvironment env,
        IMediator mediator) // added
    {
        _signInManager = signInManager;
        _userManager = userManager;
        _cookieService = cookieService;
        _dynamicCookieService = dynamicCookieService;
        _applicationManager = applicationManager;
        _db = db;
        _logger = logger;
        _configuration = configuration;
        _httpClientFactory = httpClientFactory;
        _env = env;
        _mediator = mediator; // added
    }

    private bool ShouldUseRecaptcha()
    {
        if (_env.IsDevelopment()) return false; // Always off in development
        var site = _configuration["GoogleReCaptcha:SiteKey"];
        var secret = _configuration["GoogleReCaptcha:SecretKey"];
        // Optional explicit override flag
        var enabledFlag = _configuration["GoogleReCaptcha:Enabled"];
        if (!string.IsNullOrWhiteSpace(enabledFlag) && bool.TryParse(enabledFlag, out var enabled) && !enabled)
            return false;
        return !string.IsNullOrWhiteSpace(site) && !string.IsNullOrWhiteSpace(secret);
    }

    // REMOVED: [HttpGet("authorize")] - Now handled by minimal API with client-specific cookies

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