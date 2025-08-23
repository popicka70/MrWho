using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using MrWho.Data;
using MrWho.Models;
using MrWho.Shared.Models;
using OpenIddict.Abstractions;
using MrWho.Shared;

namespace MrWho.Controllers;

[ApiController]
[Route("api/[controller]")]
[Authorize(Policy = AuthorizationPolicies.AdminClientApi)]
public class ClientsController : ControllerBase
{
    // ...existing code...
    [HttpGet]
    public async Task<ActionResult<PagedResult<ClientDto>>> GetClients(
        [FromQuery] int page = 1,
        [FromQuery] int pageSize = 10,
        [FromQuery] string? search = null,
        [FromQuery] string? realmId = null)
    {
        // ...existing code...
        var query = _context.Clients
            .Include(c => c.Realm)
            .Include(c => c.RedirectUris)
            .Include(c => c.PostLogoutUris)
            .Include(c => c.Scopes)
            .Include(c => c.Permissions)
            .Include(c => c.Audiences)
            .AsQueryable();
        // ...existing code...
            .Select(c => new ClientDto
            {
                // ...existing code...
                Audiences = c.Audiences.Select(a => a.Audience).ToList(),
                // ...existing code...
            })
        // ...existing code...
    }

    [HttpGet("{id}")]
    public async Task<ActionResult<ClientDto>> GetClient(string id)
    {
        var client = await _context.Clients
            .Include(c => c.Realm)
            .Include(c => c.RedirectUris)
            .Include(c => c.PostLogoutUris)
            .Include(c => c.Scopes)
            .Include(c => c.Permissions)
            .Include(c => c.Audiences)
            .FirstOrDefaultAsync(c => c.Id == id);
        // ...existing code...
        var clientDto = new ClientDto
        {
            // ...existing code...
            Audiences = client.Audiences.Select(a => a.Audience).ToList(),
            // ...existing code...
        };
        // ...existing code...
    }

    [HttpGet("{id}/export")]
    public async Task<ActionResult<ClientExportDto>> ExportClient(string id)
    {
        var client = await _context.Clients
            .Include(c => c.Realm)
            .Include(c => c.RedirectUris)
            .Include(c => c.PostLogoutUris)
            .Include(c => c.Scopes)
            .Include(c => c.Permissions)
            .Include(c => c.Audiences)
            .FirstOrDefaultAsync(c => c.Id == id);
        // ...existing code...
        var export = new ClientExportDto
        {
            // ...existing code...
            Audiences = client.Audiences.Select(x => x.Audience).ToList(),
            // ...existing code...
        };
        // ...existing code...
    }

    [HttpPost("import")]
    public async Task<ActionResult<ClientImportResult>> ImportClient([FromBody] ClientExportDto dto)
    {
        // ...existing code...
                var client = await _context.Clients
                    .Include(c => c.RedirectUris)
                    .Include(c => c.PostLogoutUris)
                    .Include(c => c.Scopes)
                    .Include(c => c.Permissions)
                    .Include(c => c.Audiences)
                    .FirstOrDefaultAsync(c => c.ClientId == dto.ClientId && c.RealmId == realm.Id);
        // ...existing code updating collections...
                _context.ClientAudiences.RemoveRange(client.Audiences);
                foreach (var aud in dto.Audiences.Distinct())
                {
                    _context.ClientAudiences.Add(new ClientAudience { ClientId = client.Id, Audience = aud });
                }
        // ...existing code reload full...
                    .Include(c => c.Permissions)
                    .Include(c => c.Audiences)
                    .FirstOrDefaultAsync(c => c.Id == client.Id);
                var clientDto = new ClientDto
                {
                    // ...existing code...
                    Audiences = full.Audiences.Select(a => a.Audience).ToList(),
                    // ...existing code...
                };
        // ...existing code...
    }

    [HttpPost]
    public async Task<ActionResult<ClientDto>> CreateClient([FromBody] CreateClientRequest request)
    {
        // ...existing code...
                var client = new Client
                {
                    // ...existing code...
                };
        // ...existing code after SaveChanges add collections...
                foreach (var aud in request.Audiences.Distinct())
                {
                    _context.ClientAudiences.Add(new ClientAudience { ClientId = client.Id, Audience = aud });
                }
        // ...existing code building clientDto...
                var clientDto = new ClientDto
                {
                    // ...existing code...
                    Audiences = request.Audiences.Distinct().ToList(),
                    // ...existing code...
                };
        // ...existing code...
    }

    [HttpPut("{id}")]
    public async Task<ActionResult<ClientDto>> UpdateClient(string id, [FromBody] UpdateClientRequest request)
    {
        var client = await _context.Clients
            .Include(c => c.Realm)
            .Include(c => c.RedirectUris)
            .Include(c => c.PostLogoutUris)
            .Include(c => c.Scopes)
            .Include(c => c.Permissions)
            .Include(c => c.Audiences)
            .FirstOrDefaultAsync(c => c.Id == id);
        // ...existing code...
                if (request.Audiences != null)
                {
                    _context.ClientAudiences.RemoveRange(client.Audiences);
                    foreach (var aud in request.Audiences.Distinct())
                    {
                        _context.ClientAudiences.Add(new ClientAudience { ClientId = client.Id, Audience = aud });
                    }
                }
        // ...existing code reload collections...
                await _context.Entry(client).Collection(c => c.Audiences).LoadAsync();
                var clientDto = new ClientDto
                {
                    // ...existing code...
                    Audiences = client.Audiences.Select(a => a.Audience).ToList(),
                    // ...existing code...
                };
        // ...existing code...
    }

    private async Task CreateOpenIddictApplication(Client client, CreateClientRequest request)
    {
        var descriptor = new OpenIddictApplicationDescriptor
        {
            // ...existing code...
        };
        // ...existing code adding permissions...
        foreach (var aud in request.Audiences.Distinct())
        {
            descriptor.Resources.Add(aud);
        }
        // ...existing code...
    }

    private async Task UpdateOpenIddictApplication(Client client)
    {
        // ...existing code...
            var request = new CreateClientRequest
            {
                // ...existing code...
                Audiences = client.Audiences.Select(a => a.Audience).ToList()
            };
        // ...existing code...
    }
    // ...existing code...
}
