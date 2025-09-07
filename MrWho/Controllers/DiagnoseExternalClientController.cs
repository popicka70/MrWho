using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using MrWho.Data;
using OpenIddict.Client;
using Microsoft.AspNetCore.Authorization;
using MrWho.Shared;

namespace MrWho.Controllers;

[ApiController]
[Route("api/[controller]")]
[Authorize(Policy = AuthorizationPolicies.AdminClientApi)]
public class DiagnoseExternalClientController : ControllerBase
{
    private readonly OpenIddictClientOptions _clientOptions;
    private readonly ApplicationDbContext _db;

    public DiagnoseExternalClientController(IOptions<OpenIddictClientOptions> options, ApplicationDbContext db)
    {
        _clientOptions = options.Value;
        _db = db;
    }

    [HttpGet("registrations")]
    public ActionResult<object> GetRegistrations()
    {
        var regs = _clientOptions.Registrations.Select(r => new
        {
            r.ProviderName,
            Issuer = r.Issuer?.ToString(),
            r.ClientId,
            Scopes = r.Scopes.ToArray()
        }).ToArray();
        return Ok(regs);
    }
}
