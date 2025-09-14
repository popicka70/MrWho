using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using MrWho.Data;
using MrWho.Models;
using MrWho.Shared;
using MrWho.Shared.Models;

namespace MrWho.Controllers;

[ApiController]
[Route("api/[controller]")]
[Authorize(Policy = AuthorizationPolicies.AdminClientApi)]
public class IdentityProvidersController : ControllerBase
{
    private readonly ApplicationDbContext _db;
    private readonly ILogger<IdentityProvidersController> _logger;

    public IdentityProvidersController(ApplicationDbContext db, ILogger<IdentityProvidersController> logger)
    {
        _db = db;
        _logger = logger;
    }

    // List IdPs (optionally by realm)
    [HttpGet]
    public async Task<ActionResult<IEnumerable<IdentityProviderDto>>> Get([FromQuery] string? realmId = null)
    {
        var query = _db.IdentityProviders.AsQueryable();
        if (!string.IsNullOrWhiteSpace(realmId))
        {
            query = query.Where(x => x.RealmId == realmId);
        }
        var items = await query.OrderBy(x => x.Order).ThenBy(x => x.Name).ToListAsync();
        var dtos = items.Select(MapToDto).ToList();
        return Ok(dtos);
    }

    [HttpGet("{id}")]
    public async Task<ActionResult<IdentityProviderDto>> GetOne(string id)
    {
        var item = await _db.IdentityProviders.FindAsync(id);
        if (item == null) return NotFound();
        return Ok(MapToDto(item));
    }

    [HttpPost]
    public async Task<ActionResult<IdentityProviderDto>> Create([FromBody] IdentityProviderDto dto)
    {
        if (string.IsNullOrWhiteSpace(dto.Name)) return ValidationProblem("Name is required");
        var model = MapFromDto(dto);
        model.Id = Guid.NewGuid().ToString();
        model.CreatedAt = DateTime.UtcNow;
        model.UpdatedAt = DateTime.UtcNow;
        _db.IdentityProviders.Add(model);
        await _db.SaveChangesAsync();
        return CreatedAtAction(nameof(GetOne), new { id = model.Id }, MapToDto(model));
    }

    [HttpPut("{id}")]
    public async Task<ActionResult<IdentityProviderDto>> Update(string id, [FromBody] IdentityProviderDto dto)
    {
        var existing = await _db.IdentityProviders.FindAsync(id);
        if (existing == null) return NotFound();

        // Update selected fields
        existing.Name = dto.Name;
        existing.DisplayName = dto.DisplayName;
        existing.Type = dto.Type;
        existing.IsEnabled = dto.IsEnabled;
        existing.RealmId = dto.RealmId;
        existing.IconUri = dto.IconUri;
        existing.Order = dto.Order;
        existing.Authority = dto.Authority;
        existing.MetadataAddress = dto.MetadataAddress;
        existing.ClientId = dto.ClientId;
        existing.ClientSecret = dto.ClientSecret;
        existing.Scopes = dto.Scopes;
        existing.ResponseType = dto.ResponseType;
        existing.UsePkce = dto.UsePkce;
        existing.GetClaimsFromUserInfoEndpoint = dto.GetClaimsFromUserInfoEndpoint;
        existing.ClaimMappingsJson = dto.ClaimMappingsJson;
        existing.SamlEntityId = dto.SamlEntityId;
        existing.SamlSingleSignOnUrl = dto.SamlSingleSignOnUrl;
        existing.SamlCertificate = dto.SamlCertificate;
        existing.SamlWantAssertionsSigned = dto.SamlWantAssertionsSigned;
        existing.SamlValidateIssuer = dto.SamlValidateIssuer;
        existing.UpdatedAt = DateTime.UtcNow;

        await _db.SaveChangesAsync();
        return Ok(MapToDto(existing));
    }

    [HttpDelete("{id}")]
    public async Task<IActionResult> Delete(string id)
    {
        var existing = await _db.IdentityProviders.FindAsync(id);
        if (existing == null) return NotFound();

        // Remove links first
        var links = await _db.ClientIdentityProviders.Where(x => x.IdentityProviderId == id).ToListAsync();
        _db.ClientIdentityProviders.RemoveRange(links);
        _db.IdentityProviders.Remove(existing);
        await _db.SaveChangesAsync();
        return NoContent();
    }

    // Per-client link management
    [HttpGet("{id}/clients")]
    public async Task<ActionResult<IEnumerable<ClientIdentityProviderDto>>> GetClientLinks(string id)
    {
        var links = await _db.ClientIdentityProviders
            .Where(x => x.IdentityProviderId == id)
            .Include(x => x.Client)
            .OrderBy(x => x.Order)
            .ToListAsync();
        return Ok(links.Select(MapToDto));
    }

    [HttpPost("{id}/clients/{clientId}")]
    public async Task<ActionResult<ClientIdentityProviderDto>> LinkToClient(string id, string clientId, [FromBody] ClientIdentityProviderDto? dto)
    {
        if (!await _db.IdentityProviders.AnyAsync(x => x.Id == id)) return NotFound("IdP not found");
        if (!await _db.Clients.AnyAsync(x => x.Id == clientId || x.ClientId == clientId)) return NotFound("Client not found");
        var client = await _db.Clients.FirstAsync(x => x.Id == clientId || x.ClientId == clientId);

        var link = new ClientIdentityProvider
        {
            Id = Guid.NewGuid().ToString(),
            ClientId = client.Id,
            IdentityProviderId = id,
            DisplayNameOverride = dto?.DisplayNameOverride,
            IsEnabled = dto?.IsEnabled ?? true,
            Order = dto?.Order,
            OptionsJson = dto?.OptionsJson,
            ClaimMappingsJson = dto?.ClaimMappingsJson,
            CreatedAt = DateTime.UtcNow,
            UpdatedAt = DateTime.UtcNow
        };
        _db.ClientIdentityProviders.Add(link);
        await _db.SaveChangesAsync();
        return CreatedAtAction(nameof(GetClientLinks), new { id }, MapToDto(link));
    }

    [HttpDelete("{id}/clients/{linkId}")]
    public async Task<IActionResult> UnlinkFromClient(string id, string linkId)
    {
        var link = await _db.ClientIdentityProviders.FirstOrDefaultAsync(x => x.Id == linkId && x.IdentityProviderId == id);
        if (link == null) return NotFound();
        _db.ClientIdentityProviders.Remove(link);
        await _db.SaveChangesAsync();
        return NoContent();
    }

    private static IdentityProviderDto MapToDto(IdentityProvider m) => new()
    {
        Id = m.Id,
        Name = m.Name,
        DisplayName = m.DisplayName,
        Type = m.Type,
        IsEnabled = m.IsEnabled,
        RealmId = m.RealmId,
        IconUri = m.IconUri,
        Order = m.Order,
        Authority = m.Authority,
        MetadataAddress = m.MetadataAddress,
        ClientId = m.ClientId,
        ClientSecret = m.ClientSecret,
        Scopes = m.Scopes,
        ResponseType = m.ResponseType,
        UsePkce = m.UsePkce,
        GetClaimsFromUserInfoEndpoint = m.GetClaimsFromUserInfoEndpoint,
        ClaimMappingsJson = m.ClaimMappingsJson,
        SamlEntityId = m.SamlEntityId,
        SamlSingleSignOnUrl = m.SamlSingleSignOnUrl,
        SamlCertificate = m.SamlCertificate,
        SamlWantAssertionsSigned = m.SamlWantAssertionsSigned,
        SamlValidateIssuer = m.SamlValidateIssuer
    };

    private static ClientIdentityProviderDto MapToDto(ClientIdentityProvider l) => new()
    {
        Id = l.Id,
        ClientId = l.ClientId,
        IdentityProviderId = l.IdentityProviderId,
        DisplayNameOverride = l.DisplayNameOverride,
        IsEnabled = l.IsEnabled,
        Order = l.Order,
        OptionsJson = l.OptionsJson,
        ClaimMappingsJson = l.ClaimMappingsJson
    };

    private static IdentityProvider MapFromDto(IdentityProviderDto d) => new()
    {
        Id = d.Id,
        Name = d.Name,
        DisplayName = d.DisplayName,
        Type = d.Type,
        IsEnabled = d.IsEnabled,
        RealmId = d.RealmId,
        IconUri = d.IconUri,
        Order = d.Order,
        Authority = d.Authority,
        MetadataAddress = d.MetadataAddress,
        ClientId = d.ClientId,
        ClientSecret = d.ClientSecret,
        Scopes = d.Scopes,
        ResponseType = d.ResponseType,
        UsePkce = d.UsePkce,
        GetClaimsFromUserInfoEndpoint = d.GetClaimsFromUserInfoEndpoint,
        ClaimMappingsJson = d.ClaimMappingsJson,
        SamlEntityId = d.SamlEntityId,
        SamlSingleSignOnUrl = d.SamlSingleSignOnUrl,
        SamlCertificate = d.SamlCertificate,
        SamlWantAssertionsSigned = d.SamlWantAssertionsSigned,
        SamlValidateIssuer = d.SamlValidateIssuer
    };
}
