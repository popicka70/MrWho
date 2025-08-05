using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using MrWho.Data;
using MrWho.Models;
using MrWho.Shared.Models;

namespace MrWho.Controllers;

[ApiController]
[Route("api/[controller]")]
[Authorize]
public class ApiResourcesController : ControllerBase
{
    private readonly ApplicationDbContext _context;
    private readonly ILogger<ApiResourcesController> _logger;

    public ApiResourcesController(ApplicationDbContext context, ILogger<ApiResourcesController> logger)
    {
        _context = context;
        _logger = logger;
    }

    /// <summary>
    /// Get paginated list of API resources
    /// </summary>
    [HttpGet]
    public async Task<ActionResult<PagedResult<ApiResourceDto>>> GetApiResources(
        [FromQuery] int page = 1,
        [FromQuery] int pageSize = 10,
        [FromQuery] string? search = null)
    {
        try
        {
            var query = _context.ApiResources
                .Include(ar => ar.Scopes)
                .Include(ar => ar.UserClaims)
                .Include(ar => ar.Secrets)
                .AsQueryable();

            if (!string.IsNullOrWhiteSpace(search))
            {
                query = query.Where(ar => ar.Name.Contains(search) ||
                                         (ar.DisplayName != null && ar.DisplayName.Contains(search)) ||
                                         (ar.Description != null && ar.Description.Contains(search)));
            }

            var totalCount = await query.CountAsync();
            var items = await query
                .OrderBy(ar => ar.Name)
                .Skip((page - 1) * pageSize)
                .Take(pageSize)
                .Select(ar => new ApiResourceDto
                {
                    Id = ar.Id,
                    Name = ar.Name,
                    DisplayName = ar.DisplayName,
                    Description = ar.Description,
                    IsEnabled = ar.IsEnabled,
                    IsStandard = ar.IsStandard,
                    CreatedAt = ar.CreatedAt,
                    UpdatedAt = ar.UpdatedAt,
                    CreatedBy = ar.CreatedBy,
                    UpdatedBy = ar.UpdatedBy,
                    Scopes = ar.Scopes.Select(s => s.Scope).ToList(),
                    UserClaims = ar.UserClaims.Select(c => c.ClaimType).ToList(),
                    Secrets = ar.Secrets.Select(s => new ApiSecretDto
                    {
                        Id = s.Id,
                        Description = s.Description,
                        Value = "***hidden***", // Never expose actual secret values
                        Expiration = s.Expiration,
                        Type = s.Type,
                        CreatedAt = s.CreatedAt
                    }).ToList()
                })
                .ToListAsync();

            return Ok(new PagedResult<ApiResourceDto>
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
            _logger.LogError(ex, "Error getting API resources");
            return StatusCode(500, "An error occurred while retrieving API resources");
        }
    }

    /// <summary>
    /// Get a specific API resource by ID
    /// </summary>
    [HttpGet("{id}")]
    public async Task<ActionResult<ApiResourceDto>> GetApiResource(string id)
    {
        try
        {
            var apiResource = await _context.ApiResources
                .Include(ar => ar.Scopes)
                .Include(ar => ar.UserClaims)
                .Include(ar => ar.Secrets)
                .FirstOrDefaultAsync(ar => ar.Id == id);

            if (apiResource == null)
            {
                return NotFound($"API resource with ID '{id}' not found");
            }

            var dto = new ApiResourceDto
            {
                Id = apiResource.Id,
                Name = apiResource.Name,
                DisplayName = apiResource.DisplayName,
                Description = apiResource.Description,
                IsEnabled = apiResource.IsEnabled,
                IsStandard = apiResource.IsStandard,
                CreatedAt = apiResource.CreatedAt,
                UpdatedAt = apiResource.UpdatedAt,
                CreatedBy = apiResource.CreatedBy,
                UpdatedBy = apiResource.UpdatedBy,
                Scopes = apiResource.Scopes.Select(s => s.Scope).ToList(),
                UserClaims = apiResource.UserClaims.Select(c => c.ClaimType).ToList(),
                Secrets = apiResource.Secrets.Select(s => new ApiSecretDto
                {
                    Id = s.Id,
                    Description = s.Description,
                    Value = "***hidden***", // Never expose actual secret values
                    Expiration = s.Expiration,
                    Type = s.Type,
                    CreatedAt = s.CreatedAt
                }).ToList()
            };

            return Ok(dto);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting API resource {ApiResourceId}", id);
            return StatusCode(500, "An error occurred while retrieving the API resource");
        }
    }

    /// <summary>
    /// Create a new API resource
    /// </summary>
    [HttpPost]
    public async Task<ActionResult<ApiResourceDto>> CreateApiResource([FromBody] CreateApiResourceRequest request)
    {
        try
        {
            // Check if API resource with this name already exists
            var existingApiResource = await _context.ApiResources
                .FirstOrDefaultAsync(ar => ar.Name == request.Name);

            if (existingApiResource != null)
            {
                return BadRequest($"API resource with name '{request.Name}' already exists");
            }

            var userName = User.Identity?.Name ?? "Unknown";

            var apiResource = new ApiResource
            {
                Name = request.Name,
                DisplayName = request.DisplayName,
                Description = request.Description,
                IsEnabled = request.IsEnabled,
                IsStandard = false,
                CreatedBy = userName
            };

            _context.ApiResources.Add(apiResource);
            await _context.SaveChangesAsync();

            // Add scopes
            foreach (var scope in request.Scopes)
            {
                _context.ApiResourceScopes.Add(new ApiResourceScope
                {
                    ApiResourceId = apiResource.Id,
                    Scope = scope
                });
            }

            // Add user claims
            foreach (var claim in request.UserClaims)
            {
                _context.ApiResourceClaims.Add(new ApiResourceClaim
                {
                    ApiResourceId = apiResource.Id,
                    ClaimType = claim
                });
            }

            // Add secrets
            foreach (var secret in request.Secrets)
            {
                _context.ApiResourceSecrets.Add(new ApiResourceSecret
                {
                    ApiResourceId = apiResource.Id,
                    Description = secret.Description,
                    Value = BCrypt.Net.BCrypt.HashPassword(secret.Value), // Hash the secret
                    Expiration = secret.Expiration,
                    Type = secret.Type
                });
            }

            await _context.SaveChangesAsync();

            // Reload the API resource with all related data
            var createdApiResource = await _context.ApiResources
                .Include(ar => ar.Scopes)
                .Include(ar => ar.UserClaims)
                .Include(ar => ar.Secrets)
                .FirstOrDefaultAsync(ar => ar.Id == apiResource.Id);

            var dto = new ApiResourceDto
            {
                Id = createdApiResource!.Id,
                Name = createdApiResource.Name,
                DisplayName = createdApiResource.DisplayName,
                Description = createdApiResource.Description,
                IsEnabled = createdApiResource.IsEnabled,
                IsStandard = createdApiResource.IsStandard,
                CreatedAt = createdApiResource.CreatedAt,
                UpdatedAt = createdApiResource.UpdatedAt,
                CreatedBy = createdApiResource.CreatedBy,
                UpdatedBy = createdApiResource.UpdatedBy,
                Scopes = createdApiResource.Scopes.Select(s => s.Scope).ToList(),
                UserClaims = createdApiResource.UserClaims.Select(c => c.ClaimType).ToList(),
                Secrets = createdApiResource.Secrets.Select(s => new ApiSecretDto
                {
                    Id = s.Id,
                    Description = s.Description,
                    Value = "***hidden***",
                    Expiration = s.Expiration,
                    Type = s.Type,
                    CreatedAt = s.CreatedAt
                }).ToList()
            };

            _logger.LogInformation("Created API resource '{ApiResourceName}' by user '{UserName}'", request.Name, userName);
            return CreatedAtAction(nameof(GetApiResource), new { id = dto.Id }, dto);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error creating API resource");
            return StatusCode(500, "An error occurred while creating the API resource");
        }
    }

    /// <summary>
    /// Update an existing API resource
    /// </summary>
    [HttpPut("{id}")]
    public async Task<ActionResult<ApiResourceDto>> UpdateApiResource(string id, [FromBody] UpdateApiResourceRequest request)
    {
        try
        {
            var apiResource = await _context.ApiResources
                .Include(ar => ar.Scopes)
                .Include(ar => ar.UserClaims)
                .Include(ar => ar.Secrets)
                .FirstOrDefaultAsync(ar => ar.Id == id);

            if (apiResource == null)
            {
                return NotFound($"API resource with ID '{id}' not found");
            }

            if (apiResource.IsStandard)
            {
                return BadRequest("Cannot modify standard API resources");
            }

            var userName = User.Identity?.Name ?? "Unknown";

            // Update basic properties
            if (request.DisplayName != null)
                apiResource.DisplayName = request.DisplayName;
            if (request.Description != null)
                apiResource.Description = request.Description;
            if (request.IsEnabled.HasValue)
                apiResource.IsEnabled = request.IsEnabled.Value;

            apiResource.UpdatedAt = DateTime.UtcNow;
            apiResource.UpdatedBy = userName;

            // Update scopes
            if (request.Scopes != null)
            {
                _context.ApiResourceScopes.RemoveRange(apiResource.Scopes);
                foreach (var scope in request.Scopes)
                {
                    _context.ApiResourceScopes.Add(new ApiResourceScope
                    {
                        ApiResourceId = apiResource.Id,
                        Scope = scope
                    });
                }
            }

            // Update user claims
            if (request.UserClaims != null)
            {
                _context.ApiResourceClaims.RemoveRange(apiResource.UserClaims);
                foreach (var claim in request.UserClaims)
                {
                    _context.ApiResourceClaims.Add(new ApiResourceClaim
                    {
                        ApiResourceId = apiResource.Id,
                        ClaimType = claim
                    });
                }
            }

            // Update secrets
            if (request.Secrets != null)
            {
                _context.ApiResourceSecrets.RemoveRange(apiResource.Secrets);
                foreach (var secret in request.Secrets)
                {
                    _context.ApiResourceSecrets.Add(new ApiResourceSecret
                    {
                        ApiResourceId = apiResource.Id,
                        Description = secret.Description,
                        Value = BCrypt.Net.BCrypt.HashPassword(secret.Value), // Hash the secret
                        Expiration = secret.Expiration,
                        Type = secret.Type
                    });
                }
            }

            await _context.SaveChangesAsync();

            // Reload the API resource with all related data
            var updatedApiResource = await _context.ApiResources
                .Include(ar => ar.Scopes)
                .Include(ar => ar.UserClaims)
                .Include(ar => ar.Secrets)
                .FirstOrDefaultAsync(ar => ar.Id == id);

            var dto = new ApiResourceDto
            {
                Id = updatedApiResource!.Id,
                Name = updatedApiResource.Name,
                DisplayName = updatedApiResource.DisplayName,
                Description = updatedApiResource.Description,
                IsEnabled = updatedApiResource.IsEnabled,
                IsStandard = updatedApiResource.IsStandard,
                CreatedAt = updatedApiResource.CreatedAt,
                UpdatedAt = updatedApiResource.UpdatedAt,
                CreatedBy = updatedApiResource.CreatedBy,
                UpdatedBy = updatedApiResource.UpdatedBy,
                Scopes = updatedApiResource.Scopes.Select(s => s.Scope).ToList(),
                UserClaims = updatedApiResource.UserClaims.Select(c => c.ClaimType).ToList(),
                Secrets = updatedApiResource.Secrets.Select(s => new ApiSecretDto
                {
                    Id = s.Id,
                    Description = s.Description,
                    Value = "***hidden***",
                    Expiration = s.Expiration,
                    Type = s.Type,
                    CreatedAt = s.CreatedAt
                }).ToList()
            };

            _logger.LogInformation("Updated API resource '{ApiResourceName}' by user '{UserName}'", apiResource.Name, userName);
            return Ok(dto);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error updating API resource {ApiResourceId}", id);
            return StatusCode(500, "An error occurred while updating the API resource");
        }
    }

    /// <summary>
    /// Delete an API resource
    /// </summary>
    [HttpDelete("{id}")]
    public async Task<ActionResult> DeleteApiResource(string id)
    {
        try
        {
            var apiResource = await _context.ApiResources.FirstOrDefaultAsync(ar => ar.Id == id);

            if (apiResource == null)
            {
                return NotFound($"API resource with ID '{id}' not found");
            }

            if (apiResource.IsStandard)
            {
                return BadRequest("Cannot delete standard API resources");
            }

            _context.ApiResources.Remove(apiResource);
            await _context.SaveChangesAsync();

            var userName = User.Identity?.Name ?? "Unknown";
            _logger.LogInformation("Deleted API resource '{ApiResourceName}' by user '{UserName}'", apiResource.Name, userName);

            return NoContent();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error deleting API resource {ApiResourceId}", id);
            return StatusCode(500, "An error occurred while deleting the API resource");
        }
    }

    /// <summary>
    /// Toggle API resource enabled status
    /// </summary>
    [HttpPost("{id}/toggle")]
    public async Task<ActionResult<ApiResourceDto>> ToggleApiResource(string id)
    {
        try
        {
            var apiResource = await _context.ApiResources
                .Include(ar => ar.Scopes)
                .Include(ar => ar.UserClaims)
                .Include(ar => ar.Secrets)
                .FirstOrDefaultAsync(ar => ar.Id == id);

            if (apiResource == null)
            {
                return NotFound($"API resource with ID '{id}' not found");
            }

            apiResource.IsEnabled = !apiResource.IsEnabled;
            apiResource.UpdatedAt = DateTime.UtcNow;
            apiResource.UpdatedBy = User.Identity?.Name ?? "Unknown";

            await _context.SaveChangesAsync();

            var dto = new ApiResourceDto
            {
                Id = apiResource.Id,
                Name = apiResource.Name,
                DisplayName = apiResource.DisplayName,
                Description = apiResource.Description,
                IsEnabled = apiResource.IsEnabled,
                IsStandard = apiResource.IsStandard,
                CreatedAt = apiResource.CreatedAt,
                UpdatedAt = apiResource.UpdatedAt,
                CreatedBy = apiResource.CreatedBy,
                UpdatedBy = apiResource.UpdatedBy,
                Scopes = apiResource.Scopes.Select(s => s.Scope).ToList(),
                UserClaims = apiResource.UserClaims.Select(c => c.ClaimType).ToList(),
                Secrets = apiResource.Secrets.Select(s => new ApiSecretDto
                {
                    Id = s.Id,
                    Description = s.Description,
                    Value = "***hidden***",
                    Expiration = s.Expiration,
                    Type = s.Type,
                    CreatedAt = s.CreatedAt
                }).ToList()
            };

            var status = apiResource.IsEnabled ? "enabled" : "disabled";
            _logger.LogInformation("Toggled API resource '{ApiResourceName}' to {Status}", apiResource.Name, status);

            return Ok(dto);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error toggling API resource {ApiResourceId}", id);
            return StatusCode(500, "An error occurred while toggling the API resource status");
        }
    }
}