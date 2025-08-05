using Microsoft.EntityFrameworkCore;
using MrWho.Data;
using MrWho.Models;

namespace MrWho.Services;

public interface IApiResourceSeederService
{
    Task SeedStandardApiResourcesAsync();
}

public class ApiResourceSeederService : IApiResourceSeederService
{
    private readonly ApplicationDbContext _context;
    private readonly ILogger<ApiResourceSeederService> _logger;

    public ApiResourceSeederService(ApplicationDbContext context, ILogger<ApiResourceSeederService> logger)
    {
        _context = context;
        _logger = logger;
    }

    public async Task SeedStandardApiResourcesAsync()
    {
        var standardApiResources = new[]
        {
            new StandardApiResourceDefinition
            {
                Name = "mrwho_api",
                DisplayName = "MrWho Administration API",
                Description = "Core API for MrWho OIDC server administration and management",
                Scopes = new[] { "api.read", "api.write" },
                UserClaims = new[] { "sub", "name", "email", "role" }
            },
            new StandardApiResourceDefinition
            {
                Name = "user_management_api",
                DisplayName = "User Management API",
                Description = "API for user management operations including profile updates and user administration",
                Scopes = new[] { "users.read", "users.write", "users.admin" },
                UserClaims = new[] { "sub", "name", "email", "role", "preferred_username" }
            }
        };

        foreach (var standardApiResource in standardApiResources)
        {
            var existingApiResource = await _context.ApiResources
                .Include(ar => ar.Scopes)
                .Include(ar => ar.UserClaims)
                .FirstOrDefaultAsync(ar => ar.Name == standardApiResource.Name);

            if (existingApiResource == null)
            {
                var apiResource = new ApiResource
                {
                    Name = standardApiResource.Name,
                    DisplayName = standardApiResource.DisplayName,
                    Description = standardApiResource.Description,
                    IsEnabled = true,
                    IsStandard = true,
                    CreatedBy = "System"
                };

                _context.ApiResources.Add(apiResource);
                await _context.SaveChangesAsync();

                // Add scopes
                foreach (var scope in standardApiResource.Scopes)
                {
                    _context.ApiResourceScopes.Add(new ApiResourceScope
                    {
                        ApiResourceId = apiResource.Id,
                        Scope = scope
                    });
                }

                // Add user claims
                foreach (var claim in standardApiResource.UserClaims)
                {
                    _context.ApiResourceClaims.Add(new ApiResourceClaim
                    {
                        ApiResourceId = apiResource.Id,
                        ClaimType = claim
                    });
                }

                await _context.SaveChangesAsync();
                _logger.LogInformation("Created standard API resource '{ApiResourceName}'", standardApiResource.Name);
            }
            else
            {
                // Update existing standard API resource if needed
                var needsUpdate = false;

                if (existingApiResource.DisplayName != standardApiResource.DisplayName)
                {
                    existingApiResource.DisplayName = standardApiResource.DisplayName;
                    needsUpdate = true;
                }

                if (existingApiResource.Description != standardApiResource.Description)
                {
                    existingApiResource.Description = standardApiResource.Description;
                    needsUpdate = true;
                }

                if (!existingApiResource.IsStandard)
                {
                    existingApiResource.IsStandard = true;
                    needsUpdate = true;
                }

                // Check if scopes need updating
                var existingScopes = existingApiResource.Scopes.Select(s => s.Scope).ToHashSet();
                var expectedScopes = standardApiResource.Scopes.ToHashSet();

                if (!existingScopes.SetEquals(expectedScopes))
                {
                    _context.ApiResourceScopes.RemoveRange(existingApiResource.Scopes);
                    foreach (var scope in standardApiResource.Scopes)
                    {
                        _context.ApiResourceScopes.Add(new ApiResourceScope
                        {
                            ApiResourceId = existingApiResource.Id,
                            Scope = scope
                        });
                    }
                    needsUpdate = true;
                }

                // Check if user claims need updating
                var existingClaims = existingApiResource.UserClaims.Select(c => c.ClaimType).ToHashSet();
                var expectedClaims = standardApiResource.UserClaims.ToHashSet();

                if (!existingClaims.SetEquals(expectedClaims))
                {
                    _context.ApiResourceClaims.RemoveRange(existingApiResource.UserClaims);
                    foreach (var claim in standardApiResource.UserClaims)
                    {
                        _context.ApiResourceClaims.Add(new ApiResourceClaim
                        {
                            ApiResourceId = existingApiResource.Id,
                            ClaimType = claim
                        });
                    }
                    needsUpdate = true;
                }

                if (needsUpdate)
                {
                    existingApiResource.UpdatedAt = DateTime.UtcNow;
                    existingApiResource.UpdatedBy = "System";
                    await _context.SaveChangesAsync();
                    _logger.LogInformation("Updated standard API resource '{ApiResourceName}'", standardApiResource.Name);
                }
            }
        }
    }

    private class StandardApiResourceDefinition
    {
        public string Name { get; set; } = string.Empty;
        public string DisplayName { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public string[] Scopes { get; set; } = Array.Empty<string>();
        public string[] UserClaims { get; set; } = Array.Empty<string>();
    }
}