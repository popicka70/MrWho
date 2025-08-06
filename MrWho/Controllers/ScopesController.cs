using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using MrWho.Data;
using MrWho.Models;
using MrWho.Shared.Models;
using MrWho.Services;

namespace MrWho.Controllers;

[ApiController]
[Route("api/[controller]")]
[Authorize]
public class ScopesController : ControllerBase
{
    private readonly ApplicationDbContext _context;
    private readonly IOpenIddictScopeSyncService _scopeSyncService;
    private readonly ILogger<ScopesController> _logger;

    public ScopesController(
        ApplicationDbContext context,
        IOpenIddictScopeSyncService scopeSyncService,
        ILogger<ScopesController> logger)
    {
        _context = context;
        _scopeSyncService = scopeSyncService;
        _logger = logger;
    }

    [HttpGet]
    public async Task<ActionResult<PagedResult<ScopeDto>>> GetScopes(
        [FromQuery] int page = 1,
        [FromQuery] int pageSize = 10,
        [FromQuery] string? search = null,
        [FromQuery] ScopeType? type = null)
    {
        if (page < 1) page = 1;
        if (pageSize < 1 || pageSize > 100) pageSize = 10;

        var query = _context.Scopes
            .Include(s => s.Claims)
            .AsQueryable();

        if (type.HasValue)
        {
            query = query.Where(s => s.Type == type.Value);
        }

        if (!string.IsNullOrWhiteSpace(search))
        {
            query = query.Where(s => s.Name.Contains(search) ||
                                   (s.DisplayName != null && s.DisplayName.Contains(search)) ||
                                   (s.Description != null && s.Description.Contains(search)));
        }

        var totalCount = await query.CountAsync();
        var scopes = await query
            .OrderBy(s => s.IsStandard ? 0 : 1)
            .ThenBy(s => s.Name)
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .Select(s => new ScopeDto
            {
                Id = s.Id,
                Name = s.Name,
                DisplayName = s.DisplayName,
                Description = s.Description,
                IsEnabled = s.IsEnabled,
                IsRequired = s.IsRequired,
                ShowInDiscoveryDocument = s.ShowInDiscoveryDocument,
                IsStandard = s.IsStandard,
                Type = s.Type,
                CreatedAt = s.CreatedAt,
                UpdatedAt = s.UpdatedAt,
                CreatedBy = s.CreatedBy,
                UpdatedBy = s.UpdatedBy,
                Claims = s.Claims.Select(c => c.ClaimType).ToList()
            })
            .ToListAsync();

        var result = new PagedResult<ScopeDto>
        {
            Items = scopes,
            TotalCount = totalCount,
            Page = page,
            PageSize = pageSize,
            TotalPages = (int)Math.Ceiling(totalCount / (double)pageSize)
        };

        return Ok(result);
    }

    [HttpGet("{id}")]
    public async Task<ActionResult<ScopeDto>> GetScope(string id)
    {
        var scope = await _context.Scopes
            .Include(s => s.Claims)
            .FirstOrDefaultAsync(s => s.Id == id);

        if (scope == null)
        {
            return NotFound($"Scope with ID '{id}' not found.");
        }

        var scopeDto = new ScopeDto
        {
            Id = scope.Id,
            Name = scope.Name,
            DisplayName = scope.DisplayName,
            Description = scope.Description,
            IsEnabled = scope.IsEnabled,
            IsRequired = scope.IsRequired,
            ShowInDiscoveryDocument = scope.ShowInDiscoveryDocument,
            IsStandard = scope.IsStandard,
            Type = scope.Type,
            CreatedAt = scope.CreatedAt,
            UpdatedAt = scope.UpdatedAt,
            CreatedBy = scope.CreatedBy,
            UpdatedBy = scope.UpdatedBy,
            Claims = scope.Claims.Select(c => c.ClaimType).ToList()
        };

        return Ok(scopeDto);
    }

    [HttpPost]
    public async Task<ActionResult<ScopeDto>> CreateScope([FromBody] CreateScopeRequest request)
    {
        // Check if scope name is unique
        if (await _context.Scopes.AnyAsync(s => s.Name == request.Name))
        {
            return BadRequest($"Scope with name '{request.Name}' already exists.");
        }

        // Validate scope name format
        if (!IsValidScopeName(request.Name))
        {
            return BadRequest("Scope name must contain only lowercase letters, numbers, dots, and underscores.");
        }

        var scope = new Scope
        {
            Name = request.Name,
            DisplayName = request.DisplayName,
            Description = request.Description,
            IsEnabled = request.IsEnabled,
            IsRequired = request.IsRequired,
            ShowInDiscoveryDocument = request.ShowInDiscoveryDocument,
            Type = request.Type,
            CreatedBy = User.Identity?.Name
        };

        _context.Scopes.Add(scope);
        await _context.SaveChangesAsync();

        // Add claims
        foreach (var claimType in request.Claims)
        {
            _context.ScopeClaims.Add(new ScopeClaim
            {
                ScopeId = scope.Id,
                ClaimType = claimType
            });
        }

        await _context.SaveChangesAsync();

        _logger.LogInformation("Scope '{ScopeName}' created successfully with ID {Id}", scope.Name, scope.Id);

        // CRITICAL: Synchronize the new scope with OpenIddict if it's enabled
        if (scope.IsEnabled)
        {
            try
            {
                // Reload the scope with claims to pass to OpenIddict
                var scopeWithClaims = await _context.Scopes
                    .Include(s => s.Claims)
                    .FirstAsync(s => s.Id == scope.Id);
                
                await _scopeSyncService.RegisterScopeAsync(scopeWithClaims);
                _logger.LogInformation("Successfully registered new scope '{ScopeName}' with OpenIddict", scope.Name);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to register new scope '{ScopeName}' with OpenIddict", scope.Name);
                // Note: We don't throw here as the scope was created successfully in our database
            }
        }

        var scopeDto = new ScopeDto
        {
            Id = scope.Id,
            Name = scope.Name,
            DisplayName = scope.DisplayName,
            Description = scope.Description,
            IsEnabled = scope.IsEnabled,
            IsRequired = scope.IsRequired,
            ShowInDiscoveryDocument = scope.ShowInDiscoveryDocument,
            IsStandard = scope.IsStandard,
            Type = scope.Type,
            CreatedAt = scope.CreatedAt,
            UpdatedAt = scope.UpdatedAt,
            CreatedBy = scope.CreatedBy,
            UpdatedBy = scope.UpdatedBy,
            Claims = request.Claims
        };

        return CreatedAtAction(nameof(GetScope), new { id = scope.Id }, scopeDto);
    }

    [HttpPut("{id}")]
    public async Task<ActionResult<ScopeDto>> UpdateScope(string id, [FromBody] UpdateScopeRequest request)
    {
        var scope = await _context.Scopes
            .Include(s => s.Claims)
            .FirstOrDefaultAsync(s => s.Id == id);

        if (scope == null)
        {
            return NotFound($"Scope with ID '{id}' not found.");
        }

        // Prevent modification of standard scopes
        if (scope.IsStandard)
        {
            return BadRequest("Standard scopes cannot be modified.");
        }

        // Update properties
        if (!string.IsNullOrEmpty(request.DisplayName))
            scope.DisplayName = request.DisplayName;
        scope.Description = request.Description;
        if (request.IsEnabled.HasValue)
            scope.IsEnabled = request.IsEnabled.Value;
        if (request.IsRequired.HasValue)
            scope.IsRequired = request.IsRequired.Value;
        if (request.ShowInDiscoveryDocument.HasValue)
            scope.ShowInDiscoveryDocument = request.ShowInDiscoveryDocument.Value;
        if (request.Type.HasValue)
            scope.Type = request.Type.Value;

        scope.UpdatedAt = DateTime.UtcNow;
        scope.UpdatedBy = User.Identity?.Name;

        // Update claims if provided
        if (request.Claims != null)
        {
            _context.ScopeClaims.RemoveRange(scope.Claims);
            foreach (var claimType in request.Claims)
            {
                _context.ScopeClaims.Add(new ScopeClaim
                {
                    ScopeId = scope.Id,
                    ClaimType = claimType
                });
            }
        }

        await _context.SaveChangesAsync();

        _logger.LogInformation("Scope '{ScopeName}' updated successfully", scope.Name);

        // CRITICAL: Synchronize the updated scope with OpenIddict
        try
        {
            if (scope.IsEnabled)
            {
                // Update the scope in OpenIddict
                await _scopeSyncService.RegisterScopeAsync(scope);
                _logger.LogInformation("Successfully updated scope '{ScopeName}' in OpenIddict", scope.Name);
            }
            else
            {
                // Remove disabled scope from OpenIddict
                await _scopeSyncService.RemoveScopeAsync(scope.Name);
                _logger.LogInformation("Successfully removed disabled scope '{ScopeName}' from OpenIddict", scope.Name);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to synchronize updated scope '{ScopeName}' with OpenIddict", scope.Name);
            // Note: We don't throw here as the scope was updated successfully in our database
        }

        var scopeDto = new ScopeDto
        {
            Id = scope.Id,
            Name = scope.Name,
            DisplayName = scope.DisplayName,
            Description = scope.Description,
            IsEnabled = scope.IsEnabled,
            IsRequired = scope.IsRequired,
            ShowInDiscoveryDocument = scope.ShowInDiscoveryDocument,
            IsStandard = scope.IsStandard,
            Type = scope.Type,
            CreatedAt = scope.CreatedAt,
            UpdatedAt = scope.UpdatedAt,
            CreatedBy = scope.CreatedBy,
            UpdatedBy = scope.UpdatedBy,
            Claims = scope.Claims.Select(c => c.ClaimType).ToList()
        };

        return Ok(scopeDto);
    }

    [HttpDelete("{id}")]
    public async Task<IActionResult> DeleteScope(string id)
    {
        var scope = await _context.Scopes
            .Include(s => s.Claims)
            .FirstOrDefaultAsync(s => s.Id == id);

        if (scope == null)
        {
            return NotFound($"Scope with ID '{id}' not found.");
        }

        // Prevent deletion of standard scopes
        if (scope.IsStandard)
        {
            return BadRequest("Standard scopes cannot be deleted.");
        }

        // Check if scope is being used by any clients
        var isUsedByClients = await _context.ClientScopes.AnyAsync(cs => cs.Scope == scope.Name);
        if (isUsedByClients)
        {
            return BadRequest($"Scope '{scope.Name}' is being used by one or more clients and cannot be deleted.");
        }

        var scopeName = scope.Name; // Store for logging

        _context.Scopes.Remove(scope);
        await _context.SaveChangesAsync();

        _logger.LogInformation("Scope '{ScopeName}' deleted successfully", scopeName);

        // CRITICAL: Remove the deleted scope from OpenIddict
        try
        {
            await _scopeSyncService.RemoveScopeAsync(scopeName);
            _logger.LogInformation("Successfully removed deleted scope '{ScopeName}' from OpenIddict", scopeName);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to remove deleted scope '{ScopeName}' from OpenIddict", scopeName);
            // Note: We don't throw here as the scope was deleted successfully from our database
        }

        return NoContent();
    }

    [HttpPost("{id}/toggle")]
    public async Task<ActionResult<ScopeDto>> ToggleScope(string id)
    {
        var scope = await _context.Scopes
            .Include(s => s.Claims)
            .FirstOrDefaultAsync(s => s.Id == id);

        if (scope == null)
        {
            return NotFound($"Scope with ID '{id}' not found.");
        }

        scope.IsEnabled = !scope.IsEnabled;
        scope.UpdatedAt = DateTime.UtcNow;
        scope.UpdatedBy = User.Identity?.Name;

        await _context.SaveChangesAsync();

        var action = scope.IsEnabled ? "enabled" : "disabled";
        _logger.LogInformation("Scope '{ScopeName}' {Action} successfully", scope.Name, action);

        // CRITICAL: Synchronize the toggled scope with OpenIddict
        try
        {
            if (scope.IsEnabled)
            {
                // Register the enabled scope with OpenIddict
                await _scopeSyncService.RegisterScopeAsync(scope);
                _logger.LogInformation("Successfully registered enabled scope '{ScopeName}' with OpenIddict", scope.Name);
            }
            else
            {
                // Remove the disabled scope from OpenIddict
                await _scopeSyncService.RemoveScopeAsync(scope.Name);
                _logger.LogInformation("Successfully removed disabled scope '{ScopeName}' from OpenIddict", scope.Name);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to synchronize toggled scope '{ScopeName}' with OpenIddict", scope.Name);
            // Note: We don't throw here as the scope was toggled successfully in our database
        }

        var scopeDto = new ScopeDto
        {
            Id = scope.Id,
            Name = scope.Name,
            DisplayName = scope.DisplayName,
            Description = scope.Description,
            IsEnabled = scope.IsEnabled,
            IsRequired = scope.IsRequired,
            ShowInDiscoveryDocument = scope.ShowInDiscoveryDocument,
            IsStandard = scope.IsStandard,
            Type = scope.Type,
            CreatedAt = scope.CreatedAt,
            UpdatedAt = scope.UpdatedAt,
            CreatedBy = scope.CreatedBy,
            UpdatedBy = scope.UpdatedBy,
            Claims = scope.Claims.Select(c => c.ClaimType).ToList()
        };

        return Ok(scopeDto);
    }

    [HttpGet("standard")]
    public async Task<ActionResult<List<ScopeDto>>> GetStandardScopes()
    {
        var standardScopes = await _context.Scopes
            .Include(s => s.Claims)
            .Where(s => s.IsStandard)
            .OrderBy(s => s.Name)
            .Select(s => new ScopeDto
            {
                Id = s.Id,
                Name = s.Name,
                DisplayName = s.DisplayName,
                Description = s.Description,
                IsEnabled = s.IsEnabled,
                IsRequired = s.IsRequired,
                ShowInDiscoveryDocument = s.ShowInDiscoveryDocument,
                IsStandard = s.IsStandard,
                Type = s.Type,
                CreatedAt = s.CreatedAt,
                UpdatedAt = s.UpdatedAt,
                CreatedBy = s.CreatedBy,
                UpdatedBy = s.UpdatedBy,
                Claims = s.Claims.Select(c => c.ClaimType).ToList()
            })
            .ToListAsync();

        return Ok(standardScopes);
    }

    private static bool IsValidScopeName(string name)
    {
        if (string.IsNullOrWhiteSpace(name))
            return false;

        // Scope names should only contain lowercase letters, numbers, dots, and underscores
        return name.All(c => char.IsLower(c) || char.IsDigit(c) || c == '.' || c == '_');
    }
}