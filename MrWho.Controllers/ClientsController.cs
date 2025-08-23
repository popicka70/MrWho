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

public class ClientsController : ControllerBase
{
    // ...existing code...
    [HttpGet]
    public async Task<ActionResult<PagedResult<ClientDto>>> GetClients(
        int page = 1,int pageSize = 10,string? search = null,string? realmId = null)
    {
        // ...existing code...
            .Select(c => new ClientDto
            {
                // ...existing code...
                AudienceMode = c.AudienceMode,
                PrimaryAudience = c.PrimaryAudience,
                IncludeAudInIdToken = c.IncludeAudInIdToken,
                RequireExplicitAudienceScope = c.RequireExplicitAudienceScope,
                // ...existing code...
            })
        // ...existing code...
    }

    [HttpGet("{id}")]
    public async Task<ActionResult<ClientDto>> GetClient(string id)
    {
        // ...existing code...
        var clientDto = new ClientDto
        {
            // ...existing code...
            AudienceMode = client.AudienceMode,
            PrimaryAudience = client.PrimaryAudience,
            IncludeAudInIdToken = client.IncludeAudInIdToken,
            RequireExplicitAudienceScope = client.RequireExplicitAudienceScope,
            // ...existing code...
        };
        // ...existing code...
    }

    [HttpGet("{id}/export")]
    public async Task<ActionResult<ClientExportDto>> ExportClient(string id)
    {
        // ...existing code...
        var export = new ClientExportDto
        {
            // ...existing code...
            AudienceMode = client.AudienceMode,
            PrimaryAudience = client.PrimaryAudience,
            IncludeAudInIdToken = client.IncludeAudInIdToken,
            RequireExplicitAudienceScope = client.RequireExplicitAudienceScope,
            // ...existing code...
        };
        // ...existing code...
    }

    [HttpPost("import")]
    public async Task<ActionResult<ClientImportResult>> ImportClient(ClientExportDto dto)
    {
        // ...existing code...
                // Update simple props
                // ...existing code...
                client.AudienceMode = dto.AudienceMode;
                client.PrimaryAudience = dto.PrimaryAudience;
                client.IncludeAudInIdToken = dto.IncludeAudInIdToken;
                client.RequireExplicitAudienceScope = dto.RequireExplicitAudienceScope;
                // ...existing code...
                var clientDto = new ClientDto
                {
                    // ...existing code...
                    AudienceMode = full.AudienceMode,
                    PrimaryAudience = full.PrimaryAudience,
                    IncludeAudInIdToken = full.IncludeAudInIdToken,
                    RequireExplicitAudienceScope = full.RequireExplicitAudienceScope,
                    // ...existing code...
                };
        // ...existing code...
    }

    [HttpPost]
    public async Task<ActionResult<ClientDto>> CreateClient(CreateClientRequest request)
    {
        // ...existing code...
                var client = new Client
                {
                    // ...existing code...
                    AudienceMode = request.AudienceMode,
                    PrimaryAudience = request.PrimaryAudience,
                    IncludeAudInIdToken = request.IncludeAudInIdToken,
                    RequireExplicitAudienceScope = request.RequireExplicitAudienceScope
                };
        // ...existing code building clientDto...
                var clientDto = new ClientDto
                {
                    // ...existing code...
                    AudienceMode = client.AudienceMode,
                    PrimaryAudience = client.PrimaryAudience,
                    IncludeAudInIdToken = client.IncludeAudInIdToken,
                    RequireExplicitAudienceScope = client.RequireExplicitAudienceScope,
                    // ...existing code...
                };
        // ...existing code...
    }

    [HttpPut("{id}")]
    public async Task<ActionResult<ClientDto>> UpdateClient(string id, UpdateClientRequest request)
    {
        // ...existing code...
                if (request.AudienceMode.HasValue) client.AudienceMode = request.AudienceMode.Value;
                if (request.PrimaryAudience != null) client.PrimaryAudience = request.PrimaryAudience;
                if (request.IncludeAudInIdToken.HasValue) client.IncludeAudInIdToken = request.IncludeAudInIdToken;
                if (request.RequireExplicitAudienceScope.HasValue) client.RequireExplicitAudienceScope = request.RequireExplicitAudienceScope;
        // ...existing code reload...
                var clientDto = new ClientDto
                {
                    // ...existing code...
                    AudienceMode = client.AudienceMode,
                    PrimaryAudience = client.PrimaryAudience,
                    IncludeAudInIdToken = client.IncludeAudInIdToken,
                    RequireExplicitAudienceScope = client.RequireExplicitAudienceScope,
                    // ...existing code...
                };
        // ...existing code...
    }
    // ...existing code...
}
