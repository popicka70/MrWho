using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using OpenIddict.Client;
using OpenIddict.Client.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using MrWho.Services.Mediator;
using MrWho.Endpoints;
using MrWho.Handlers.Auth; // add for InvalidScopesGetRequest
using MrWho.Data; // added
using MrWho.Models; // added for PushedAuthorizationRequest
using MrWho.Shared; // added for PushedAuthorizationMode
using OpenIddict.Abstractions; // added for OpenIddictConstants
using Microsoft.EntityFrameworkCore; // added for EF calls
using MrWho.Services; // added for ISecurityAuditWriter & SecurityAudit

namespace MrWho.Controllers;

[AllowAnonymous]
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
        if (!string.IsNullOrWhiteSpace(returnUrl)) props.Items["returnUrl"] = returnUrl;
        if (!string.IsNullOrWhiteSpace(clientId)) props.Items["clientId"] = clientId;
        props.Items["extRegistrationId"] = registration.RegistrationId;
        if (!string.IsNullOrWhiteSpace(registration.ProviderName)) props.Items["extProviderName"] = registration.ProviderName;
        props.Items[OpenIddictClientAspNetCoreConstants.Properties.RegistrationId] = registration.RegistrationId;
        if (!string.IsNullOrEmpty(force) && (force == "1" || force.Equals("true", StringComparison.OrdinalIgnoreCase)))
        {
            props.Parameters["prompt"] = "login";
            props.Parameters["max_age"] = 0;
        }
        return Challenge(props, OpenIddictClientAspNetCoreDefaults.AuthenticationScheme);
    }

    // GET /connect/external/signout
    [HttpGet("external/signout")]
    public IActionResult ExternalSignOut()
    {
        var regId = HttpContext.Session.GetString("ExternalRegistrationId") ?? User?.FindFirst("ext_reg_id")?.Value;
        if (string.IsNullOrWhiteSpace(regId)) return NoContent();
        var props = new AuthenticationProperties { RedirectUri = "/connect/external/signout-callback" };
        props.Items[OpenIddictClientAspNetCoreConstants.Properties.RegistrationId] = regId;
        return SignOut(props, OpenIddictClientAspNetCoreDefaults.AuthenticationScheme);
    }

    // GET or POST /connect/authorize passthrough via mediator
    [HttpGet("authorize")]
    [HttpPost("authorize")]
    public async Task<IActionResult> AuthorizeEndpoint()
        => Wrap(await _mediator.Send(new OidcAuthorizeRequest(HttpContext)));

    // POST /connect/token passthrough via mediator
    [HttpPost("token")]
    public async Task<IActionResult> TokenEndpoint()
        => Wrap(await _mediator.Send(new OidcTokenRequest(HttpContext)));

    // GET /connect/invalid-scopes
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

    // POST /connect/par  (Pushed Authorization Request)
    [HttpPost("par")]
    public async Task<IActionResult> PushedAuthorizationRequest()
    {
        try
        {
            if (!Request.HasFormContentType)
            {
                return BadRequest(new { error = OpenIddictConstants.Errors.InvalidRequest, error_description = "Form content required" });
            }
            var form = await Request.ReadFormAsync();
            var clientId = form[OpenIddictConstants.Parameters.ClientId].ToString();
            if (string.IsNullOrWhiteSpace(clientId))
            {
                return BadRequest(new { error = OpenIddictConstants.Errors.InvalidClient, error_description = "client_id missing" });
            }
            var client = await _db.Clients.AsNoTracking().FirstOrDefaultAsync(c => c.ClientId == clientId);
            if (client == null || !client.IsEnabled)
            {
                return BadRequest(new { error = OpenIddictConstants.Errors.InvalidClient, error_description = "unknown client" });
            }
            var parMode = client.ParMode ?? PushedAuthorizationMode.Disabled;
            if (parMode == PushedAuthorizationMode.Disabled)
            {
                return BadRequest(new { error = OpenIddictConstants.Errors.InvalidRequest, error_description = "PAR disabled for client" });
            }
            // Collect raw parameters (excluding client_secret for security)
            var dict = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (var kvp in form)
            {
                if (string.Equals(kvp.Key, OpenIddictConstants.Parameters.ClientSecret, StringComparison.OrdinalIgnoreCase)) continue;
                dict[kvp.Key] = kvp.Value.ToString();
            }
            var json = System.Text.Json.JsonSerializer.Serialize(dict);
            // Hash parameters for integrity
            string hash;
            using (var sha = System.Security.Cryptography.SHA256.Create())
            {
                hash = Convert.ToHexString(sha.ComputeHash(System.Text.Encoding.UTF8.GetBytes(json)));
            }
            var par = new PushedAuthorizationRequest
            {
                ClientId = clientId,
                ParametersJson = json,
                ExpiresAt = DateTime.UtcNow.AddSeconds(90),
                ParametersHash = hash
            };
            par.RequestUri = "urn:ietf:params:oauth:request_uri:" + par.Id;
            _db.Add(par);
            await _db.SaveChangesAsync();
            try { await _audit.WriteAsync(SecurityAudit.ParAccepted, new { clientId, requestUri = par.RequestUri, expiresAt = par.ExpiresAt }, "info", actorClientId: clientId); } catch { }
            return StatusCode(StatusCodes.Status201Created, new { request_uri = par.RequestUri, expires_in = (int)(par.ExpiresAt - DateTime.UtcNow).TotalSeconds });
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "PAR endpoint failure");
            return BadRequest(new { error = OpenIddictConstants.Errors.InvalidRequest, error_description = "PAR processing error" });
        }
    }

    private IActionResult Wrap(IResult result) => new ResultWrapper(result);

    private sealed class ResultWrapper : IActionResult
    {
        private readonly IResult _inner;
        public ResultWrapper(IResult inner) => _inner = inner;
        public Task ExecuteResultAsync(ActionContext context) => _inner.ExecuteAsync(context.HttpContext);
    }
}
