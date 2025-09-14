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
public class IdentityResourcesController : ControllerBase
{
    private readonly ApplicationDbContext _context;
    private readonly ILogger<IdentityResourcesController> _logger;

    public IdentityResourcesController(ApplicationDbContext context, ILogger<IdentityResourcesController> logger)
    {
        _context = context;
        _logger = logger;
    }

    /// <summary>
    /// Creates an IdentityResourceClaimDto from an IdentityResourceClaim entity
    /// </summary>
    private static IdentityResourceClaimDto CreateClaimDto(IdentityResourceClaim entity)
    {
        var standardClaim = CommonClaimTypes.StandardClaims.FirstOrDefault(s => s.Type == entity.ClaimType);

        return new IdentityResourceClaimDto
        {
            Id = entity.Id,
            IdentityResourceId = entity.IdentityResourceId,
            ClaimType = entity.ClaimType,
            DisplayName = standardClaim?.DisplayName ?? ToTitleCase(entity.ClaimType.Replace("_", " ")),
            Description = standardClaim?.Description ?? "Custom claim type",
            IsStandard = standardClaim != null
        };
    }

    /// <summary>
    /// Helper method for title case conversion
    /// </summary>
    private static string ToTitleCase(string input)
    {
        if (string.IsNullOrEmpty(input)) {
            return input;
        }

        return System.Globalization.CultureInfo.CurrentCulture.TextInfo.ToTitleCase(input.ToLower());
    }

    /// <summary>
    /// Get paginated list of identity resources
    /// </summary>
    [HttpGet]
    public async Task<ActionResult<PagedResult<IdentityResourceDto>>> GetIdentityResources(
        [FromQuery] int page = 1,
        [FromQuery] int pageSize = 10,
        [FromQuery] string? search = null)
    {
        try
        {
            var query = _context.IdentityResources
                .Include(ir => ir.UserClaims)
                .Include(ir => ir.Properties)
                .AsQueryable();

            if (!string.IsNullOrWhiteSpace(search))
            {
                query = query.Where(ir => ir.Name.Contains(search) ||
                                         (ir.DisplayName != null && ir.DisplayName.Contains(search)) ||
                                         (ir.Description != null && ir.Description.Contains(search)));
            }

            var totalCount = await query.CountAsync();

            // First load the entities from database
            var identityResources = await query
                .OrderBy(ir => ir.Name)
                .Skip((page - 1) * pageSize)
                .Take(pageSize)
                .ToListAsync();

            // Then create DTOs in memory where we can use ToDictionary
            var items = identityResources.Select(ir => new IdentityResourceDto
            {
                Id = ir.Id,
                Name = ir.Name,
                DisplayName = ir.DisplayName,
                Description = ir.Description,
                IsEnabled = ir.IsEnabled,
                IsRequired = ir.IsRequired,
                IsStandard = ir.IsStandard,
                ShowInDiscoveryDocument = ir.ShowInDiscoveryDocument,
                Emphasize = ir.Emphasize,
                CreatedAt = ir.CreatedAt,
                UpdatedAt = ir.UpdatedAt,
                CreatedBy = ir.CreatedBy,
                UpdatedBy = ir.UpdatedBy,
                UserClaims = ir.UserClaims.Select(c => CreateClaimDto(c)).ToList(),
                Properties = ir.Properties.ToDictionary(p => p.Key, p => p.Value)
            }).ToList();

            return Ok(new PagedResult<IdentityResourceDto>
            {
                Items = items,
                TotalCount = totalCount,
                Page = page,
                PageSize = pageSize,
                TotalPages = (int)Math.Ceiling((double)totalCount / pageSize)
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting identity resources");
            return StatusCode(500, "An error occurred while retrieving identity resources");
        }
    }

    /// <summary>
    /// Get a specific identity resource by ID
    /// </summary>
    [HttpGet("{id}")]
    public async Task<ActionResult<IdentityResourceDto>> GetIdentityResource(string id)
    {
        try
        {
            var identityResource = await _context.IdentityResources
                .Include(ir => ir.UserClaims)
                .Include(ir => ir.Properties)
                .FirstOrDefaultAsync(ir => ir.Id == id);

            if (identityResource == null)
            {
                return NotFound($"Identity resource with ID '{id}' not found");
            }

            // Create DTO in memory to allow ToDictionary
            var dto = new IdentityResourceDto
            {
                Id = identityResource.Id,
                Name = identityResource.Name,
                DisplayName = identityResource.DisplayName,
                Description = identityResource.Description,
                IsEnabled = identityResource.IsEnabled,
                IsRequired = identityResource.IsRequired,
                IsStandard = identityResource.IsStandard,
                ShowInDiscoveryDocument = identityResource.ShowInDiscoveryDocument,
                Emphasize = identityResource.Emphasize,
                CreatedAt = identityResource.CreatedAt,
                UpdatedAt = identityResource.UpdatedAt,
                CreatedBy = identityResource.CreatedBy,
                UpdatedBy = identityResource.UpdatedBy,
                UserClaims = identityResource.UserClaims.Select(c => CreateClaimDto(c)).ToList(),
                Properties = identityResource.Properties.ToDictionary(p => p.Key, p => p.Value)
            };

            return Ok(dto);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting identity resource {IdentityResourceId}", id);
            return StatusCode(500, "An error occurred while retrieving the identity resource");
        }
    }

    /// <summary>
    /// Create a new identity resource
    /// </summary>
    [HttpPost]
    public async Task<ActionResult<IdentityResourceDto>> CreateIdentityResource([FromBody] CreateIdentityResourceRequest request)
    {
        try
        {
            // Check if identity resource with this name already exists
            var existingIdentityResource = await _context.IdentityResources
                .FirstOrDefaultAsync(ir => ir.Name == request.Name);

            if (existingIdentityResource != null)
            {
                return BadRequest($"Identity resource with name '{request.Name}' already exists");
            }

            var userName = User.Identity?.Name ?? "Unknown";

            var identityResource = new IdentityResource
            {
                Name = request.Name,
                DisplayName = request.DisplayName,
                Description = request.Description,
                IsEnabled = request.IsEnabled,
                IsRequired = request.IsRequired,
                IsStandard = false,
                ShowInDiscoveryDocument = request.ShowInDiscoveryDocument,
                Emphasize = request.Emphasize,
                CreatedBy = userName
            };

            _context.IdentityResources.Add(identityResource);
            await _context.SaveChangesAsync();

            // Add user claims
            foreach (var claim in request.UserClaims)
            {
                _context.IdentityResourceClaims.Add(new IdentityResourceClaim
                {
                    IdentityResourceId = identityResource.Id,
                    ClaimType = claim
                });
            }

            // Add properties
            foreach (var property in request.Properties)
            {
                _context.IdentityResourceProperties.Add(new IdentityResourceProperty
                {
                    IdentityResourceId = identityResource.Id,
                    Key = property.Key,
                    Value = property.Value
                });
            }

            await _context.SaveChangesAsync();

            // Reload the identity resource with all related data
            var createdIdentityResource = await _context.IdentityResources
                .Include(ir => ir.UserClaims)
                .Include(ir => ir.Properties)
                .FirstOrDefaultAsync(ir => ir.Id == identityResource.Id);

            // Create DTO in memory to allow ToDictionary
            var dto = new IdentityResourceDto
            {
                Id = createdIdentityResource!.Id,
                Name = createdIdentityResource.Name,
                DisplayName = createdIdentityResource.DisplayName,
                Description = createdIdentityResource.Description,
                IsEnabled = createdIdentityResource.IsEnabled,
                IsRequired = createdIdentityResource.IsRequired,
                IsStandard = createdIdentityResource.IsStandard,
                ShowInDiscoveryDocument = createdIdentityResource.ShowInDiscoveryDocument,
                Emphasize = createdIdentityResource.Emphasize,
                CreatedAt = createdIdentityResource.CreatedAt,
                UpdatedAt = createdIdentityResource.UpdatedAt,
                CreatedBy = createdIdentityResource.CreatedBy,
                UpdatedBy = createdIdentityResource.UpdatedBy,
                UserClaims = createdIdentityResource.UserClaims.Select(c => CreateClaimDto(c)).ToList(),
                Properties = createdIdentityResource.Properties.ToDictionary(p => p.Key, p => p.Value)
            };

            _logger.LogInformation("Created identity resource '{IdentityResourceName}' by user '{UserName}'", request.Name, userName);
            return CreatedAtAction(nameof(GetIdentityResource), new { id = dto.Id }, dto);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error creating identity resource");
            return StatusCode(500, "An error occurred while creating the identity resource");
        }
    }

    /// <summary>
    /// Update an existing identity resource
    /// </summary>
    [HttpPut("{id}")]
    public async Task<ActionResult<IdentityResourceDto>> UpdateIdentityResource(string id, [FromBody] UpdateIdentityResourceRequest request)
    {
        try
        {
            var identityResource = await _context.IdentityResources
                .Include(ir => ir.UserClaims)
                .Include(ir => ir.Properties)
                .FirstOrDefaultAsync(ir => ir.Id == id);

            if (identityResource == null)
            {
                return NotFound($"Identity resource with ID '{id}' not found");
            }

            if (identityResource.IsStandard)
            {
                return BadRequest("Cannot modify standard identity resources");
            }

            var userName = User.Identity?.Name ?? "Unknown";

            // Update basic properties
            if (request.DisplayName != null) {
                identityResource.DisplayName = request.DisplayName;
            }

            if (request.Description != null) {
                identityResource.Description = request.Description;
            }

            if (request.IsEnabled.HasValue) {
                identityResource.IsEnabled = request.IsEnabled.Value;
            }

            if (request.IsRequired.HasValue) {
                identityResource.IsRequired = request.IsRequired.Value;
            }

            if (request.ShowInDiscoveryDocument.HasValue) {
                identityResource.ShowInDiscoveryDocument = request.ShowInDiscoveryDocument.Value;
            }

            if (request.Emphasize.HasValue) {
                identityResource.Emphasize = request.Emphasize.Value;
            }

            identityResource.UpdatedAt = DateTime.UtcNow;
            identityResource.UpdatedBy = userName;

            // Update user claims
            if (request.UserClaims != null)
            {
                _context.IdentityResourceClaims.RemoveRange(identityResource.UserClaims);
                foreach (var claim in request.UserClaims)
                {
                    _context.IdentityResourceClaims.Add(new IdentityResourceClaim
                    {
                        IdentityResourceId = identityResource.Id,
                        ClaimType = claim
                    });
                }
            }

            // Update properties
            if (request.Properties != null)
            {
                _context.IdentityResourceProperties.RemoveRange(identityResource.Properties);
                foreach (var property in request.Properties)
                {
                    _context.IdentityResourceProperties.Add(new IdentityResourceProperty
                    {
                        IdentityResourceId = identityResource.Id,
                        Key = property.Key,
                        Value = property.Value
                    });
                }
            }

            await _context.SaveChangesAsync();

            // Reload the identity resource with all related data
            var updatedIdentityResource = await _context.IdentityResources
                .Include(ir => ir.UserClaims)
                .Include(ir => ir.Properties)
                .FirstOrDefaultAsync(ir => ir.Id == id);

            // Create DTO in memory to allow ToDictionary
            var dto = new IdentityResourceDto
            {
                Id = updatedIdentityResource!.Id,
                Name = updatedIdentityResource.Name,
                DisplayName = updatedIdentityResource.DisplayName,
                Description = updatedIdentityResource.Description,
                IsEnabled = updatedIdentityResource.IsEnabled,
                IsRequired = updatedIdentityResource.IsRequired,
                IsStandard = updatedIdentityResource.IsStandard,
                ShowInDiscoveryDocument = updatedIdentityResource.ShowInDiscoveryDocument,
                Emphasize = updatedIdentityResource.Emphasize,
                CreatedAt = updatedIdentityResource.CreatedAt,
                UpdatedAt = updatedIdentityResource.UpdatedAt,
                CreatedBy = updatedIdentityResource.CreatedBy,
                UpdatedBy = updatedIdentityResource.UpdatedBy,
                UserClaims = updatedIdentityResource.UserClaims.Select(c => CreateClaimDto(c)).ToList(),
                Properties = updatedIdentityResource.Properties.ToDictionary(p => p.Key, p => p.Value)
            };

            _logger.LogInformation("Updated identity resource '{IdentityResourceName}' by user '{UserName}'", identityResource.Name, userName);
            return Ok(dto);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error updating identity resource {IdentityResourceId}", id);
            return StatusCode(500, "An error occurred while updating the identity resource");
        }
    }

    /// <summary>
    /// Delete an identity resource
    /// </summary>
    [HttpDelete("{id}")]
    public async Task<ActionResult> DeleteIdentityResource(string id)
    {
        try
        {
            var identityResource = await _context.IdentityResources.FirstOrDefaultAsync(ir => ir.Id == id);

            if (identityResource == null)
            {
                return NotFound($"Identity resource with ID '{id}' not found");
            }

            if (identityResource.IsStandard)
            {
                return BadRequest("Cannot delete standard identity resources");
            }

            _context.IdentityResources.Remove(identityResource);
            await _context.SaveChangesAsync();

            var userName = User.Identity?.Name ?? "Unknown";
            _logger.LogInformation("Deleted identity resource '{IdentityResourceName}' by user '{UserName}'", identityResource.Name, userName);

            return NoContent();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error deleting identity resource {IdentityResourceId}", id);
            return StatusCode(500, "An error occurred while deleting the identity resource");
        }
    }

    /// <summary>
    /// Toggle identity resource enabled status
    /// </summary>
    [HttpPost("{id}/toggle")]
    public async Task<ActionResult<IdentityResourceDto>> ToggleIdentityResource(string id)
    {
        try
        {
            var identityResource = await _context.IdentityResources
                .Include(ir => ir.UserClaims)
                .Include(ir => ir.Properties)
                .FirstOrDefaultAsync(ir => ir.Id == id);

            if (identityResource == null)
            {
                return NotFound($"Identity resource with ID '{id}' not found");
            }

            identityResource.IsEnabled = !identityResource.IsEnabled;
            identityResource.UpdatedAt = DateTime.UtcNow;
            identityResource.UpdatedBy = User.Identity?.Name ?? "Unknown";

            await _context.SaveChangesAsync();

            // Create DTO in memory to allow ToDictionary
            var dto = new IdentityResourceDto
            {
                Id = identityResource.Id,
                Name = identityResource.Name,
                DisplayName = identityResource.DisplayName,
                Description = identityResource.Description,
                IsEnabled = identityResource.IsEnabled,
                IsRequired = identityResource.IsRequired,
                IsStandard = identityResource.IsStandard,
                ShowInDiscoveryDocument = identityResource.ShowInDiscoveryDocument,
                Emphasize = identityResource.Emphasize,
                CreatedAt = identityResource.CreatedAt,
                UpdatedAt = identityResource.UpdatedAt,
                CreatedBy = identityResource.CreatedBy,
                UpdatedBy = identityResource.UpdatedBy,
                UserClaims = identityResource.UserClaims.Select(c => CreateClaimDto(c)).ToList(),
                Properties = identityResource.Properties.ToDictionary(p => p.Key, p => p.Value)
            };

            var status = identityResource.IsEnabled ? "enabled" : "disabled";
            _logger.LogInformation("Toggled identity resource '{IdentityResourceName}' to {Status}", identityResource.Name, status);

            return Ok(dto);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error toggling identity resource {IdentityResourceId}", id);
            return StatusCode(500, "An error occurred while toggling the identity resource status");
        }
    }
}