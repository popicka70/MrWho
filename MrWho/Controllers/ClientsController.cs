using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using MrWho.Data;
using MrWho.Models;
using MrWho.Shared.Models;
using OpenIddict.Abstractions;

namespace MrWho.Controllers;

[ApiController]
[Route("api/[controller]")]
[Authorize]
public class ClientsController : ControllerBase
{
    private readonly ApplicationDbContext _context;
    private readonly ILogger<ClientsController> _logger;
    private readonly IOpenIddictApplicationManager _applicationManager;

    public ClientsController(
        ApplicationDbContext context, 
        ILogger<ClientsController> logger,
        IOpenIddictApplicationManager applicationManager)
    {
        _context = context;
        _logger = logger;
        _applicationManager = applicationManager;
    }

    [HttpGet]
    public async Task<ActionResult<PagedResult<ClientDto>>> GetClients(
        [FromQuery] int page = 1,
        [FromQuery] int pageSize = 10,
        [FromQuery] string? search = null,
        [FromQuery] string? realmId = null)
    {
        if (page < 1) page = 1;
        if (pageSize < 1 || pageSize > 100) pageSize = 10;

        var query = _context.Clients
            .Include(c => c.Realm)
            .Include(c => c.RedirectUris)
            .Include(c => c.PostLogoutUris)
            .Include(c => c.Scopes)
            .Include(c => c.Permissions)
            .AsQueryable();

        if (!string.IsNullOrWhiteSpace(realmId))
        {
            query = query.Where(c => c.RealmId == realmId);
        }

        if (!string.IsNullOrWhiteSpace(search))
        {
            query = query.Where(c => c.ClientId.Contains(search) || 
                                   c.Name.Contains(search) ||
                                   (c.Description != null && c.Description.Contains(search)));
        }

        var totalCount = await query.CountAsync();
        var clients = await query
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .Select(c => new ClientDto
            {
                Id = c.Id,
                ClientId = c.ClientId,
                Name = c.Name,
                Description = c.Description,
                IsEnabled = c.IsEnabled,
                ClientType = c.ClientType, // Remove cast since now using shared enum
                AllowAuthorizationCodeFlow = c.AllowAuthorizationCodeFlow,
                AllowClientCredentialsFlow = c.AllowClientCredentialsFlow,
                AllowPasswordFlow = c.AllowPasswordFlow,
                AllowRefreshTokenFlow = c.AllowRefreshTokenFlow,
                RequirePkce = c.RequirePkce,
                RequireClientSecret = c.RequireClientSecret,
                AccessTokenLifetime = c.AccessTokenLifetime,
                RefreshTokenLifetime = c.RefreshTokenLifetime,
                AuthorizationCodeLifetime = c.AuthorizationCodeLifetime,
                RealmId = c.RealmId,
                RealmName = c.Realm.Name,
                CreatedAt = c.CreatedAt,
                UpdatedAt = c.UpdatedAt,
                CreatedBy = c.CreatedBy,
                UpdatedBy = c.UpdatedBy,
                RedirectUris = c.RedirectUris.Select(ru => ru.Uri).ToList(),
                PostLogoutUris = c.PostLogoutUris.Select(plu => plu.Uri).ToList(),
                Scopes = c.Scopes.Select(s => s.Scope).ToList(),
                Permissions = c.Permissions.Select(p => p.Permission).ToList()
            })
            .ToListAsync();

        var result = new PagedResult<ClientDto>
        {
            Items = clients,
            TotalCount = totalCount,
            Page = page,
            PageSize = pageSize,
            TotalPages = (int)Math.Ceiling(totalCount / (double)pageSize)
        };

        return Ok(result);
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
            .FirstOrDefaultAsync(c => c.Id == id);

        if (client == null)
        {
            return NotFound($"Client with ID '{id}' not found.");
        }

        var clientDto = new ClientDto
        {
            Id = client.Id,
            ClientId = client.ClientId,
            Name = client.Name,
            Description = client.Description,
            IsEnabled = client.IsEnabled,
            ClientType = client.ClientType, // Remove cast since now using shared enum
            AllowAuthorizationCodeFlow = client.AllowAuthorizationCodeFlow,
            AllowClientCredentialsFlow = client.AllowClientCredentialsFlow,
            AllowPasswordFlow = client.AllowPasswordFlow,
            AllowRefreshTokenFlow = client.AllowRefreshTokenFlow,
            RequirePkce = client.RequirePkce,
            RequireClientSecret = client.RequireClientSecret,
            AccessTokenLifetime = client.AccessTokenLifetime,
            RefreshTokenLifetime = client.RefreshTokenLifetime,
            AuthorizationCodeLifetime = client.AuthorizationCodeLifetime,
            RealmId = client.RealmId,
            RealmName = client.Realm.Name,
            CreatedAt = client.CreatedAt,
            UpdatedAt = client.UpdatedAt,
            CreatedBy = client.CreatedBy,
            UpdatedBy = client.UpdatedBy,
            RedirectUris = client.RedirectUris.Select(ru => ru.Uri).ToList(),
            PostLogoutUris = client.PostLogoutUris.Select(plu => plu.Uri).ToList(),
            Scopes = client.Scopes.Select(s => s.Scope).ToList(),
            Permissions = client.Permissions.Select(p => p.Permission).ToList()
        };

        return Ok(clientDto);
    }

    [HttpPost]
    public async Task<ActionResult<ClientDto>> CreateClient([FromBody] CreateClientRequest request)
    {
        // Verify realm exists
        var realm = await _context.Realms.FindAsync(request.RealmId);
        if (realm == null)
        {
            return BadRequest($"Realm with ID '{request.RealmId}' not found.");
        }

        // Check if client ID is unique
        if (await _context.Clients.AnyAsync(c => c.ClientId == request.ClientId))
        {
            return BadRequest($"Client with ID '{request.ClientId}' already exists.");
        }

        var strategy = _context.Database.CreateExecutionStrategy();
        var result = await strategy.ExecuteAsync(async () =>
        {
            using var transaction = await _context.Database.BeginTransactionAsync();
            try
            {
                var client = new Client
                {
                    ClientId = request.ClientId,
                    ClientSecret = request.ClientSecret,
                    Name = request.Name,
                    Description = request.Description,
                    RealmId = request.RealmId,
                    IsEnabled = request.IsEnabled,
                    ClientType = request.ClientType, // Remove cast since now using shared enum
                    AllowAuthorizationCodeFlow = request.AllowAuthorizationCodeFlow,
                    AllowClientCredentialsFlow = request.AllowClientCredentialsFlow,
                    AllowPasswordFlow = request.AllowPasswordFlow,
                    AllowRefreshTokenFlow = request.AllowRefreshTokenFlow,
                    RequirePkce = request.RequirePkce,
                    RequireClientSecret = request.RequireClientSecret,
                    AccessTokenLifetime = request.AccessTokenLifetime,
                    RefreshTokenLifetime = request.RefreshTokenLifetime,
                    AuthorizationCodeLifetime = request.AuthorizationCodeLifetime,
                    CreatedBy = User.Identity?.Name
                };

                _context.Clients.Add(client);
                await _context.SaveChangesAsync();

                // Add redirect URIs
                foreach (var uri in request.RedirectUris)
                {
                    _context.ClientRedirectUris.Add(new ClientRedirectUri
                    {
                        ClientId = client.Id,
                        Uri = uri
                    });
                }

                // Add post-logout URIs
                foreach (var uri in request.PostLogoutUris)
                {
                    _context.ClientPostLogoutUris.Add(new ClientPostLogoutUri
                    {
                        ClientId = client.Id,
                        Uri = uri
                    });
                }

                // Add scopes
                foreach (var scope in request.Scopes)
                {
                    _context.ClientScopes.Add(new ClientScope
                    {
                        ClientId = client.Id,
                        Scope = scope
                    });
                }

                // Add permissions
                foreach (var permission in request.Permissions)
                {
                    _context.ClientPermissions.Add(new ClientPermission
                    {
                        ClientId = client.Id,
                        Permission = permission
                    });
                }

                await _context.SaveChangesAsync();

                // Create OpenIddict application
                await CreateOpenIddictApplication(client, request);

                await transaction.CommitAsync();

                _logger.LogInformation("Client '{ClientId}' created successfully with ID {Id}", client.ClientId, client.Id);

                var clientDto = new ClientDto
                {
                    Id = client.Id,
                    ClientId = client.ClientId,
                    Name = client.Name,
                    Description = client.Description,
                    IsEnabled = client.IsEnabled,
                    ClientType = client.ClientType, // Remove cast since now using shared enum
                    AllowAuthorizationCodeFlow = client.AllowAuthorizationCodeFlow,
                    AllowClientCredentialsFlow = client.AllowClientCredentialsFlow,
                    AllowPasswordFlow = client.AllowPasswordFlow,
                    AllowRefreshTokenFlow = client.AllowRefreshTokenFlow,
                    RequirePkce = client.RequirePkce,
                    RequireClientSecret = client.RequireClientSecret,
                    AccessTokenLifetime = client.AccessTokenLifetime,
                    RefreshTokenLifetime = client.RefreshTokenLifetime,
                    AuthorizationCodeLifetime = client.AuthorizationCodeLifetime,
                    RealmId = client.RealmId,
                    RealmName = realm.Name,
                    CreatedAt = client.CreatedAt,
                    UpdatedAt = client.UpdatedAt,
                    CreatedBy = client.CreatedBy,
                    UpdatedBy = client.UpdatedBy,
                    RedirectUris = request.RedirectUris,
                    PostLogoutUris = request.PostLogoutUris,
                    Scopes = request.Scopes,
                    Permissions = request.Permissions
                };

                return CreatedAtAction(nameof(GetClient), new { id = client.Id }, clientDto);
            }
            catch (Exception ex)
            {
                await transaction.RollbackAsync();
                _logger.LogError(ex, "Error creating client '{ClientId}'", request.ClientId);
                throw;
            }
        });

        return result;
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
            .FirstOrDefaultAsync(c => c.Id == id);

        if (client == null)
        {
            return NotFound($"Client with ID '{id}' not found.");
        }

        // Use execution strategy for transaction handling with retry support
        var strategy = _context.Database.CreateExecutionStrategy();
        var result = await strategy.ExecuteAsync(async () =>
        {
            using var transaction = await _context.Database.BeginTransactionAsync();
            try
            {
                // Update basic properties
                if (!string.IsNullOrEmpty(request.ClientSecret))
                    client.ClientSecret = request.ClientSecret;
                if (!string.IsNullOrEmpty(request.Name))
                    client.Name = request.Name;
                client.Description = request.Description;
                if (request.IsEnabled.HasValue)
                    client.IsEnabled = request.IsEnabled.Value;
                if (request.ClientType.HasValue)
                    client.ClientType = request.ClientType.Value; // Remove cast since now using shared enum
                if (request.AllowAuthorizationCodeFlow.HasValue)
                    client.AllowAuthorizationCodeFlow = request.AllowAuthorizationCodeFlow.Value;
                if (request.AllowClientCredentialsFlow.HasValue)
                    client.AllowClientCredentialsFlow = request.AllowClientCredentialsFlow.Value;
                if (request.AllowPasswordFlow.HasValue)
                    client.AllowPasswordFlow = request.AllowPasswordFlow.Value;
                if (request.AllowRefreshTokenFlow.HasValue)
                    client.AllowRefreshTokenFlow = request.AllowRefreshTokenFlow.Value;
                if (request.RequirePkce.HasValue)
                    client.RequirePkce = request.RequirePkce.Value;
                if (request.RequireClientSecret.HasValue)
                    client.RequireClientSecret = request.RequireClientSecret.Value;

                client.AccessTokenLifetime = request.AccessTokenLifetime;
                client.RefreshTokenLifetime = request.RefreshTokenLifetime;
                client.AuthorizationCodeLifetime = request.AuthorizationCodeLifetime;
                client.UpdatedAt = DateTime.UtcNow;
                client.UpdatedBy = User.Identity?.Name;

                // Update redirect URIs if provided
                if (request.RedirectUris != null)
                {
                    _context.ClientRedirectUris.RemoveRange(client.RedirectUris);
                    foreach (var uri in request.RedirectUris)
                    {
                        _context.ClientRedirectUris.Add(new ClientRedirectUri
                        {
                            ClientId = client.Id,
                            Uri = uri
                        });
                    }
                }

                // Update post-logout URIs if provided
                if (request.PostLogoutUris != null)
                {
                    _context.ClientPostLogoutUris.RemoveRange(client.PostLogoutUris);
                    foreach (var uri in request.PostLogoutUris)
                    {
                        _context.ClientPostLogoutUris.Add(new ClientPostLogoutUri
                        {
                            ClientId = client.Id,
                            Uri = uri
                        });
                    }
                }

                // Update scopes if provided
                if (request.Scopes != null)
                {
                    _context.ClientScopes.RemoveRange(client.Scopes);
                    foreach (var scope in request.Scopes)
                    {
                        _context.ClientScopes.Add(new ClientScope
                        {
                            ClientId = client.Id,
                            Scope = scope
                        });
                    }
                }

                // Update permissions if provided
                if (request.Permissions != null)
                {
                    _context.ClientPermissions.RemoveRange(client.Permissions);
                    foreach (var permission in request.Permissions)
                    {
                        _context.ClientPermissions.Add(new ClientPermission
                        {
                            ClientId = client.Id,
                            Permission = permission
                        });
                    }
                }

                await _context.SaveChangesAsync();
                _logger.LogInformation("Client '{ClientId}' updated in database", client.ClientId);
                
                // Update OpenIddict application
                await UpdateOpenIddictApplication(client);

                await transaction.CommitAsync();

                _logger.LogInformation("Client '{ClientId}' updated successfully", client.ClientId);

                // Reload client with updated data
                await _context.Entry(client).ReloadAsync();
                
                var clientDto = new ClientDto
                {
                    Id = client.Id,
                    ClientId = client.ClientId,
                    Name = client.Name,
                    Description = client.Description,
                    IsEnabled = client.IsEnabled,
                    ClientType = client.ClientType, // Remove cast since now using shared enum
                    AllowAuthorizationCodeFlow = client.AllowAuthorizationCodeFlow,
                    AllowClientCredentialsFlow = client.AllowClientCredentialsFlow,
                    AllowPasswordFlow = client.AllowPasswordFlow,
                    AllowRefreshTokenFlow = client.AllowRefreshTokenFlow,
                    RequirePkce = client.RequirePkce,
                    RequireClientSecret = client.RequireClientSecret,
                    AccessTokenLifetime = client.AccessTokenLifetime,
                    RefreshTokenLifetime = client.RefreshTokenLifetime,
                    AuthorizationCodeLifetime = client.AuthorizationCodeLifetime,
                    RealmId = client.RealmId,
                    RealmName = client.Realm.Name,
                    CreatedAt = client.CreatedAt,
                    UpdatedAt = client.UpdatedAt,
                    CreatedBy = client.CreatedBy,
                    UpdatedBy = client.UpdatedBy,
                    RedirectUris = client.RedirectUris.Select(ru => ru.Uri).ToList(),
                    PostLogoutUris = client.PostLogoutUris.Select(plu => plu.Uri).ToList(),
                    Scopes = client.Scopes.Select(s => s.Scope).ToList(),
                    Permissions = client.Permissions.Select(p => p.Permission).ToList()
                };

                return clientDto;
            }
            catch (Exception ex)
            {
                await transaction.RollbackAsync();
                _logger.LogError(ex, "Error updating client '{ClientId}'", client.ClientId);
                throw;
            }
        });

        return Ok(result);
    }

    [HttpDelete("{id}")]
    public async Task<IActionResult> DeleteClient(string id)
    {
        var client = await _context.Clients.FindAsync(id);
        if (client == null)
        {
            return NotFound($"Client with ID '{id}' not found.");
        }

        // Use execution strategy for transaction handling with retry support
        var strategy = _context.Database.CreateExecutionStrategy();
        await strategy.ExecuteAsync(async () =>
        {
            using var transaction = await _context.Database.BeginTransactionAsync();
            try
            {
                // Delete from OpenIddict
                var openIddictClient = await _applicationManager.FindByClientIdAsync(client.ClientId);
                if (openIddictClient != null)
                {
                    await _applicationManager.DeleteAsync(openIddictClient);
                }

                // Delete from our database (cascade will handle related entities)
                _context.Clients.Remove(client);
                await _context.SaveChangesAsync();

                await transaction.CommitAsync();

                _logger.LogInformation("Client '{ClientId}' deleted successfully", client.ClientId);
            }
            catch (Exception ex)
            {
                await transaction.RollbackAsync();
                _logger.LogError(ex, "Error deleting client '{ClientId}'", client.ClientId);
                throw;
            }
        });

        return NoContent();
    }

    [HttpPost("{id}/toggle")]
    public async Task<ActionResult<ClientDto>> ToggleClient(string id)
    {
        var client = await _context.Clients
            .Include(c => c.Realm)
            .Include(c => c.RedirectUris)
            .Include(c => c.PostLogoutUris)
            .Include(c => c.Scopes)
            .Include(c => c.Permissions)
            .FirstOrDefaultAsync(c => c.Id == id);

        if (client == null)
        {
            return NotFound($"Client with ID '{id}' not found.");
        }

        client.IsEnabled = !client.IsEnabled;
        client.UpdatedAt = DateTime.UtcNow;
        client.UpdatedBy = User.Identity?.Name;

        await _context.SaveChangesAsync();

        var action = client.IsEnabled ? "enabled" : "disabled";
        _logger.LogInformation("Client '{ClientId}' {Action} successfully", client.ClientId, action);

        var clientDto = new ClientDto
        {
            Id = client.Id,
            ClientId = client.ClientId,
            Name = client.Name,
            Description = client.Description,
            IsEnabled = client.IsEnabled,
            ClientType = client.ClientType, // Remove cast since now using shared enum
            AllowAuthorizationCodeFlow = client.AllowAuthorizationCodeFlow,
            AllowClientCredentialsFlow = client.AllowClientCredentialsFlow,
            AllowPasswordFlow = client.AllowPasswordFlow,
            AllowRefreshTokenFlow = client.AllowRefreshTokenFlow,
            RequirePkce = client.RequirePkce,
            RequireClientSecret = client.RequireClientSecret,
            AccessTokenLifetime = client.AccessTokenLifetime,
            RefreshTokenLifetime = client.RefreshTokenLifetime,
            AuthorizationCodeLifetime = client.AuthorizationCodeLifetime,
            RealmId = client.RealmId,
            RealmName = client.Realm.Name,
            CreatedAt = client.CreatedAt,
            UpdatedAt = client.UpdatedAt,
            CreatedBy = client.CreatedBy,
            UpdatedBy = client.UpdatedBy,
            RedirectUris = client.RedirectUris.Select(ru => ru.Uri).ToList(),
            PostLogoutUris = client.PostLogoutUris.Select(plu => plu.Uri).ToList(),
            Scopes = client.Scopes.Select(s => s.Scope).ToList(),
            Permissions = client.Permissions.Select(p => p.Permission).ToList()
        };

        return Ok(clientDto);
    }

    private async Task CreateOpenIddictApplication(Client client, CreateClientRequest request)
    {
        var descriptor = new OpenIddictApplicationDescriptor
        {
            ClientId = client.ClientId,
            ClientSecret = client.ClientSecret,
            DisplayName = client.Name
        };

        // Add permissions based on flows
        if (client.AllowAuthorizationCodeFlow)
        {
            descriptor.Permissions.Add(OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode);
            descriptor.Permissions.Add(OpenIddictConstants.Permissions.Endpoints.Authorization);
            descriptor.Permissions.Add(OpenIddictConstants.Permissions.ResponseTypes.Code);
        }

        if (client.AllowClientCredentialsFlow)
        {
            descriptor.Permissions.Add(OpenIddictConstants.Permissions.GrantTypes.ClientCredentials);
        }

        if (client.AllowPasswordFlow)
        {
            descriptor.Permissions.Add(OpenIddictConstants.Permissions.GrantTypes.Password);
        }

        if (client.AllowRefreshTokenFlow)
        {
            descriptor.Permissions.Add(OpenIddictConstants.Permissions.GrantTypes.RefreshToken);
        }

        descriptor.Permissions.Add(OpenIddictConstants.Permissions.Endpoints.Token);

        // Add scopes and permissions
        foreach (var scope in request.Scopes)
        {
            if (scope == "openid")
                descriptor.Permissions.Add("oidc:scope:openid");
            else if (scope == "email")
                descriptor.Permissions.Add(OpenIddictConstants.Permissions.Scopes.Email);
            else if (scope == "profile")
                descriptor.Permissions.Add(OpenIddictConstants.Permissions.Scopes.Profile);
            else if (scope == "roles")
                descriptor.Permissions.Add(OpenIddictConstants.Permissions.Scopes.Roles);
        }

        foreach (var permission in request.Permissions)
        {
            descriptor.Permissions.Add(permission);
        }

        // Add redirect URIs
        foreach (var uri in request.RedirectUris)
        {
            descriptor.RedirectUris.Add(new Uri(uri));
        }

        // Add post-logout redirect URIs
        foreach (var uri in request.PostLogoutUris)
        {
            descriptor.PostLogoutRedirectUris.Add(new Uri(uri));
        }

        await _applicationManager.CreateAsync(descriptor);
    }

    private async Task UpdateOpenIddictApplication(Client client)
    {
        var openIddictClient = await _applicationManager.FindByClientIdAsync(client.ClientId);
        if (openIddictClient != null)
        {
            // For simplicity, we'll recreate the OpenIddict application
            // In production, you might want to update it in place
            await _applicationManager.DeleteAsync(openIddictClient);
            
            var request = new CreateClientRequest
            {
                ClientId = client.ClientId,
                ClientSecret = client.ClientSecret,
                Name = client.Name,
                Description = client.Description,
                RealmId = client.RealmId,
                ClientType = client.ClientType, // Remove cast since now using shared enum
                RedirectUris = client.RedirectUris.Select(ru => ru.Uri).ToList(),
                PostLogoutUris = client.PostLogoutUris.Select(plu => plu.Uri).ToList(),
                Scopes = client.Scopes.Select(s => s.Scope).ToList(),
                Permissions = client.Permissions.Select(p => p.Permission).ToList()
            };
            
            await CreateOpenIddictApplication(client, request);
        }
    }
}