using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore; // added for EF calls
using Microsoft.Extensions.Options;
using MrWho.Data; // added
using MrWho.Endpoints;
using MrWho.Handlers.Auth; // add for InvalidScopesGetRequest
using MrWho.Models; // added for PushedAuthorizationRequest
using MrWho.Services; // added for ISecurityAuditWriter & SecurityAudit
using MrWho.Services.Mediator;
using MrWho.Shared; // added for PushedAuthorizationMode
using OpenIddict.Abstractions; // added for OpenIddictConstants
using OpenIddict.Client;
using OpenIddict.Client.AspNetCore;

namespace MrWho.Controllers;

[Route("connect")] // base route
public class ConnectController : Controller
{
    private readonly IOptionsMonitor<OpenIddictClientOptions> _clientOptions;
    private readonly IMediator _mediator;
    private readonly ILogger<ConnectController> _logger;
    private readonly ApplicationDbContext _db; // added
    private readonly ISecurityAuditWriter _audit; // added

    public ConnectController(IOptionsMonitor<OpenIddictClientOptions> clientOptions, IMediator mediator, ILogger<ConnectController> logger, ApplicationDbContext db, ISecurityAuditWriter audit)
    {
        _clientOptions = clientOptions;
        _mediator = mediator;
        _logger = logger;
        _db = db;
        _audit = audit;
    }

    // GET /connect/external/login/{provider}
    [AllowAnonymous]
    [HttpGet("external/login/{provider}")]
    public IActionResult ExternalLogin(string provider, [FromQuery] string? returnUrl = null, [FromQuery] string? clientId = null, [FromQuery] string? force = null)
    {
        var registrations = _clientOptions.CurrentValue.Registrations;
        var registration = registrations.FirstOrDefault(r => !string.IsNullOrWhiteSpace(r.ProviderName) && string.Equals(r.ProviderName, provider, StringComparison.OrdinalIgnoreCase))
            ?? registrations.FirstOrDefault(r => r.Issuer is not null && (string.Equals(r.Issuer.Host, provider, StringComparison.OrdinalIgnoreCase) || string.Equals(r.Issuer.AbsoluteUri.TrimEnd('/'), provider.TrimEnd('/'), StringComparison.OrdinalIgnoreCase)))
            ?? registrations.FirstOrDefault(r => !string.IsNullOrWhiteSpace(r.RegistrationId) && string.Equals(r.RegistrationId, provider, StringComparison.OrdinalIgnoreCase));

        if (registration is null)
        {
            Response.StatusCode = StatusCodes.Status400BadRequest;
            return Content($"Unknown external provider '{provider}'.");
        }

        var props = new AuthenticationProperties { RedirectUri = "/connect/external/callback" };
        if (!string.IsNullOrWhiteSpace(returnUrl)) {
            props.Items["returnUrl"] = returnUrl;
        }

        if (!string.IsNullOrWhiteSpace(clientId)) {
            props.Items["clientId"] = clientId;
        }

        props.Items["extRegistrationId"] = registration.RegistrationId;
        if (!string.IsNullOrWhiteSpace(registration.ProviderName)) {
            props.Items["extProviderName"] = registration.ProviderName;
        }

        props.Items[OpenIddictClientAspNetCoreConstants.Properties.RegistrationId] = registration.RegistrationId;
        if (!string.IsNullOrEmpty(force) && (force == "1" || force.Equals("true", StringComparison.OrdinalIgnoreCase)))
        {
            props.Parameters["prompt"] = "login";
            props.Parameters["max_age"] = 0;
        }
        return Challenge(props, OpenIddictClientAspNetCoreDefaults.AuthenticationScheme);
    }

    // GET /connect/external/signout
    [AllowAnonymous]
    [HttpGet("external/signout")]
    public IActionResult ExternalSignOut()
    {
        var regId = HttpContext.Session.GetString("ExternalRegistrationId") ?? User?.FindFirst("ext_reg_id")?.Value;
        if (string.IsNullOrWhiteSpace(regId)) {
            return NoContent();
        }

        var props = new AuthenticationProperties { RedirectUri = "/connect/external/signout-callback" };
        props.Items[OpenIddictClientAspNetCoreConstants.Properties.RegistrationId] = regId;
        return SignOut(props, OpenIddictClientAspNetCoreDefaults.AuthenticationScheme);
    }

    // GET or POST /connect/authorize
    [AllowAnonymous]
    [HttpGet("authorize")]
    [HttpPost("authorize")]
    public async Task<IActionResult> AuthorizeEndpoint()
        => Wrap(await _mediator.Send(new OidcAuthorizeRequest(HttpContext)));

    // POST /connect/token
    [AllowAnonymous]
    [HttpPost("token")]
    public async Task<IActionResult> TokenEndpoint()
        => Wrap(await _mediator.Send(new OidcTokenRequest(HttpContext)));

    // GET /connect/invalid-scopes
    [AllowAnonymous]
    [HttpGet("invalid-scopes")]
    public Task<IActionResult> InvalidScopes([FromQuery] string? returnUrl, [FromQuery] string? clientId, [FromQuery] string? missing, [FromQuery] string? requested)
        => _mediator.Send(new InvalidScopesGetRequest(HttpContext, returnUrl, clientId, missing, requested));

    // GET /connect/consent
    [Authorize]
    [HttpGet("consent")]
    public Task<IActionResult> Consent([FromQuery] string returnUrl, [FromQuery] string clientId, [FromQuery] string? requested)
        => _mediator.Send(new MrWho.Handlers.Auth.ConsentGetRequest(HttpContext, returnUrl, clientId, requested));

    // POST /connect/consent
    [Authorize]
    [ValidateAntiForgeryToken]
    [HttpPost("consent")]
    public Task<IActionResult> ConsentPost([FromForm] string returnUrl, [FromForm] string clientId, [FromForm] string[] scopes, [FromForm] bool remember)
        => _mediator.Send(new MrWho.Handlers.Auth.ConsentPostRequest(HttpContext, returnUrl, clientId, scopes, remember));

    // POST /connect/consent/forget
    [Authorize]
    [ValidateAntiForgeryToken]
    [HttpPost("consent/forget")]
    public Task<IActionResult> ConsentForget([FromForm] string clientId)
        => _mediator.Send(new MrWho.Handlers.Auth.ConsentForgetRequest(HttpContext, clientId));

    private IActionResult Wrap(IResult result) => new ResultWrapper(result);

    private sealed class ResultWrapper : IActionResult
    {
        private readonly IResult _inner;
        public ResultWrapper(IResult inner) => _inner = inner;
        public Task ExecuteResultAsync(ActionContext context) => _inner.ExecuteAsync(context.HttpContext);
    }
}
