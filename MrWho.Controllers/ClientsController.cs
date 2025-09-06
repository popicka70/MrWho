using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using MrWho.Data;
using MrWho.Models;
using MrWho.Shared.Models;
using OpenIddict.Abstractions;
using MrWho.Shared;
using System.Linq; // ensure LINQ

namespace MrWho.Controllers;

public class ClientsController : ControllerBase
{
    // ...existing fields/ctor...

    [HttpGet]
    public async Task<ActionResult<PagedResult<ClientDto>>> GetClients(
        int page = 1,int pageSize = 10,string? search = null,string? realmId = null)
    {
        // ...existing pre-query logic...
        var query = _db.Clients
            .Include(c => c.Audiences)
            // ...existing includes...
            .AsQueryable();
        // ...existing filtering/paging logic...
        var items = await query
            .Skip((page-1)*pageSize)
            .Take(pageSize)
            .Select(c => new ClientDto
            {
                // ...existing mapped properties before audiences...
                ParMode = c.ParMode,
                Audiences = c.Audiences.Select(a => a.Audience).ToList(),
                AudienceMode = c.AudienceMode,
                PrimaryAudience = c.PrimaryAudience,
                IncludeAudInIdToken = c.IncludeAudInIdToken,
                RequireExplicitAudienceScope = c.RequireExplicitAudienceScope,
                RoleInclusionOverride = c.RoleInclusionOverride,
                AllowPasswordFlow = c.AllowPasswordFlow,
                AllowRefreshTokenFlow = c.AllowRefreshTokenFlow,
                AllowDeviceCodeFlow = c.AllowDeviceCodeFlow,
                RequirePkce = c.RequirePkce
                // ...existing mapped properties after audiences...
            })
            .ToListAsync();
        // ...existing return building PagedResult...
    }

    [HttpGet("{id}")]
    public async Task<ActionResult<ClientDto>> GetClient(string id)
    {
        var client = await _db.Clients
            .Include(c => c.Audiences)
            // ...existing includes...
            .FirstOrDefaultAsync(c => c.Id == id || c.ClientId == id);
        if (client == null) return NotFound();
        var dto = new ClientDto
        {
            // ...existing mappings...
            ParMode = client.ParMode,
            Audiences = client.Audiences.Select(a => a.Audience).ToList(),
            AudienceMode = client.AudienceMode,
            PrimaryAudience = client.PrimaryAudience,
            IncludeAudInIdToken = client.IncludeAudInIdToken,
            RequireExplicitAudienceScope = client.RequireExplicitAudienceScope,
            RoleInclusionOverride = client.RoleInclusionOverride,
            AllowPasswordFlow = client.AllowPasswordFlow,
            AllowRefreshTokenFlow = client.AllowRefreshTokenFlow,
            AllowDeviceCodeFlow = client.AllowDeviceCodeFlow,
            RequirePkce = client.RequirePkce
            // ...existing mappings...
        };
        return dto;
    }

    [HttpPost]
    public async Task<ActionResult<ClientDto>> CreateClient(CreateClientRequest request)
    {
        // ...existing validation logic...
        var client = new Client
        {
            // ...existing assignments...
            ParMode = request.ParMode,
            AudienceMode = request.AudienceMode,
            PrimaryAudience = request.PrimaryAudience,
            IncludeAudInIdToken = request.IncludeAudInIdToken,
            RequireExplicitAudienceScope = request.RequireExplicitAudienceScope,
            RoleInclusionOverride = request.RoleInclusionOverride,
            AllowPasswordFlow = request.AllowPasswordFlow,
            AllowRefreshTokenFlow = request.AllowRefreshTokenFlow,
            AllowDeviceCodeFlow = request.AllowDeviceCodeFlow,
            RequirePkce = request.RequirePkce
        };
        // Audiences
        if (request.Audiences?.Any() == true)
        {
            foreach (var aud in request.Audiences.Where(a => !string.IsNullOrWhiteSpace(a)).Distinct(StringComparer.OrdinalIgnoreCase))
            {
                client.Audiences.Add(new ClientAudience { Audience = aud.Trim() });
            }
        }
        _db.Clients.Add(client);
        await _db.SaveChangesAsync();
        // Build dto
        var dto = new ClientDto
        {
            // ...existing mappings...
            ParMode = client.ParMode,
            Audiences = client.Audiences.Select(a => a.Audience).ToList(),
            AudienceMode = client.AudienceMode,
            PrimaryAudience = client.PrimaryAudience,
            IncludeAudInIdToken = client.IncludeAudInIdToken,
            RequireExplicitAudienceScope = client.RequireExplicitAudienceScope,
            RoleInclusionOverride = client.RoleInclusionOverride,
            AllowPasswordFlow = client.AllowPasswordFlow,
            AllowRefreshTokenFlow = client.AllowRefreshTokenFlow,
            AllowDeviceCodeFlow = client.AllowDeviceCodeFlow,
            RequirePkce = client.RequirePkce
            // ...existing mappings...
        };
        return CreatedAtAction(nameof(GetClient), new { id = client.Id }, dto);
    }

    [HttpPut("{id}")]
    public async Task<ActionResult<ClientDto>> UpdateClient(string id, UpdateClientRequest request)
    {
        var client = await _db.Clients
            .Include(c => c.Audiences)
            // ...existing includes...
            .FirstOrDefaultAsync(c => c.Id == id || c.ClientId == id);
        if (client == null) return NotFound();
        // ...existing property updates...
        if (request.ParMode.HasValue) client.ParMode = request.ParMode;
        if (request.AudienceMode.HasValue) client.AudienceMode = request.AudienceMode;
        if (request.PrimaryAudience != null) client.PrimaryAudience = request.PrimaryAudience;
        if (request.IncludeAudInIdToken.HasValue) client.IncludeAudInIdToken = request.IncludeAudInIdToken;
        if (request.RequireExplicitAudienceScope.HasValue) client.RequireExplicitAudienceScope = request.RequireExplicitAudienceScope;
        if (request.RoleInclusionOverride != null) client.RoleInclusionOverride = request.RoleInclusionOverride;
        if (request.AllowPasswordFlow.HasValue) client.AllowPasswordFlow = request.AllowPasswordFlow.Value;
        if (request.AllowRefreshTokenFlow.HasValue) client.AllowRefreshTokenFlow = request.AllowRefreshTokenFlow.Value;
        if (request.AllowDeviceCodeFlow.HasValue) client.AllowDeviceCodeFlow = request.AllowDeviceCodeFlow.Value;
        if (request.RequirePkce.HasValue) client.RequirePkce = request.RequirePkce.Value;
        // Sync audiences list
        if (request.Audiences != null)
        {
            var incoming = request.Audiences.Where(a => !string.IsNullOrWhiteSpace(a)).Select(a => a.Trim()).Distinct(StringComparer.OrdinalIgnoreCase).ToHashSet(StringComparer.OrdinalIgnoreCase);
            var toRemove = client.Audiences.Where(a => !incoming.Contains(a.Audience)).ToList();
            foreach (var rem in toRemove) client.Audiences.Remove(rem);
            var existing = client.Audiences.Select(a => a.Audience).ToHashSet(StringComparer.OrdinalIgnoreCase);
            foreach (var aud in incoming)
            {
                if (!existing.Contains(aud)) client.Audiences.Add(new ClientAudience { Audience = aud });
            }
        }
        await _db.SaveChangesAsync();
        var dto = new ClientDto
        {
            // ...existing mappings...
            ParMode = client.ParMode,
            Audiences = client.Audiences.Select(a => a.Audience).ToList(),
            AudienceMode = client.AudienceMode,
            PrimaryAudience = client.PrimaryAudience,
            IncludeAudInIdToken = client.IncludeAudInIdToken,
            RequireExplicitAudienceScope = client.RequireExplicitAudienceScope,
            RoleInclusionOverride = client.RoleInclusionOverride,
            AllowPasswordFlow = client.AllowPasswordFlow,
            AllowRefreshTokenFlow = client.AllowRefreshTokenFlow,
            AllowDeviceCodeFlow = client.AllowDeviceCodeFlow,
            RequirePkce = client.RequirePkce
            // ...existing mappings...
        };
        return dto;
    }

    [HttpGet("{id}/export")]
    public async Task<ActionResult<ClientExportDto>> ExportClient(string id)
    {
        var client = await _db.Clients.Include(c=>c.Audiences).FirstOrDefaultAsync(c=>c.Id==id || c.ClientId==id);
        if (client == null) return NotFound();
        var export = new ClientExportDto
        {
            // ...existing mappings...
            ParMode = client.ParMode,
            Audiences = client.Audiences.Select(a=>a.Audience).ToList(),
            AudienceMode = client.AudienceMode,
            PrimaryAudience = client.PrimaryAudience,
            IncludeAudInIdToken = client.IncludeAudInIdToken,
            RequireExplicitAudienceScope = client.RequireExplicitAudienceScope,
            RoleInclusionOverride = client.RoleInclusionOverride,
            AllowPasswordFlow = client.AllowPasswordFlow,
            AllowRefreshTokenFlow = client.AllowRefreshTokenFlow,
            AllowDeviceCodeFlow = client.AllowDeviceCodeFlow,
            RequirePkce = client.RequirePkce,
            // ...existing mappings...
        };
        return export;
    }

    [HttpPost("import")]
    public async Task<ActionResult<ClientImportResult>> ImportClient(ClientExportDto dto)
    {
        // ...existing logic before applying simple props...
        // After locating client entity 'client'
        client.ParMode = dto.ParMode;
        client.AudienceMode = dto.AudienceMode;
        client.PrimaryAudience = dto.PrimaryAudience;
        client.IncludeAudInIdToken = dto.IncludeAudInIdToken;
        client.RequireExplicitAudienceScope = dto.RequireExplicitAudienceScope;
        client.RoleInclusionOverride = dto.RoleInclusionOverride;
        client.AllowPasswordFlow = dto.AllowPasswordFlow;
        client.AllowRefreshTokenFlow = dto.AllowRefreshTokenFlow;
        client.AllowDeviceCodeFlow = dto.AllowDeviceCodeFlow;
        client.RequirePkce = dto.RequirePkce;
        // Sync audiences from export
        if (dto.Audiences != null)
        {
            var incoming = dto.Audiences.Where(a => !string.IsNullOrWhiteSpace(a)).Select(a => a.Trim()).Distinct(StringComparer.OrdinalIgnoreCase).ToHashSet(StringComparer.OrdinalIgnoreCase);
            var toRemove = client.Audiences.Where(a => !incoming.Contains(a.Audience)).ToList();
            foreach (var rem in toRemove) client.Audiences.Remove(rem);
            var existing = client.Audiences.Select(a => a.Audience).ToHashSet(StringComparer.OrdinalIgnoreCase);
            foreach (var aud in incoming)
            {
                if (!existing.Contains(aud)) client.Audiences.Add(new ClientAudience { Audience = aud });
            }
        }
        await _db.SaveChangesAsync();
        // ...existing build of result dto...
        // Ensure returned dto includes audiences/config
        // ...existing code...
    }
}
