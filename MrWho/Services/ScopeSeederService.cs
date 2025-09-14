using Microsoft.EntityFrameworkCore;
using MrWho.Data;
using MrWho.Models;
using MrWho.Shared.Models;

namespace MrWho.Services;

/// <summary>
/// Service responsible for seeding standard scopes into the database.
/// This service focuses solely on database operations and does not handle OpenIddict synchronization.
/// </summary>
public interface IScopeSeederService
{
    /// <summary>
    /// Initializes standard scopes in the database
    /// </summary>
    Task InitializeStandardScopesAsync();

    /// <summary>
    /// Initializes standard identity resources in the database
    /// </summary>
    Task InitializeStandardIdentityResourcesAsync();
}

/// <summary>
/// Service responsible for seeding standard scopes into the database.
/// This service focuses solely on database operations and does not handle OpenIddict synchronization.
/// </summary>
public class ScopeSeederService : IScopeSeederService
{
    private readonly ApplicationDbContext _context;
    private readonly ILogger<ScopeSeederService> _logger;

    public ScopeSeederService(
        ApplicationDbContext context,
        ILogger<ScopeSeederService> logger)
    {
        _context = context;
        _logger = logger;
    }

    /// <summary>
    /// Initializes standard scopes in the database
    /// </summary>
    public async Task InitializeStandardScopesAsync()
    {
        var standardScopes = new[]
        {
            new StandardScopeDefinition
            {
                Name = "openid",
                DisplayName = "OpenID",
                Description = "Access to OpenID Connect identity",
                IsRequired = true,
                Type = ScopeType.Identity,
                Claims = new[] { "sub" }
            },
            new StandardScopeDefinition
            {
                Name = "profile",
                DisplayName = "Profile",
                Description = "Access to profile information",
                Type = ScopeType.Identity,
                Claims = new[] { "name", "family_name", "given_name", "middle_name", "nickname", "preferred_username", "profile", "picture", "website", "gender", "birthdate", "zoneinfo", "locale", "updated_at" }
            },
            new StandardScopeDefinition
            {
                Name = "email",
                DisplayName = "Email",
                Description = "Access to email address",
                Type = ScopeType.Identity,
                Claims = new[] { "email", "email_verified" }
            },
            new StandardScopeDefinition
            {
                Name = "roles",
                DisplayName = "Roles",
                Description = "Access to user roles",
                Type = ScopeType.Identity,
                Claims = new[] { "role" }
            },
            new StandardScopeDefinition
            {
                Name = "offline_access",
                DisplayName = "Offline Access",
                Description = "Request refresh token / offline access",
                Type = ScopeType.Resource,
                Claims = Array.Empty<string>()
            },
            new StandardScopeDefinition
            {
                Name = "api.read",
                DisplayName = "API Read Access",
                Description = "Read access to API resources",
                Type = ScopeType.Resource,
                Claims = new[] { "scope" }
            },
            new StandardScopeDefinition
            {
                Name = "api.write",
                DisplayName = "API Write Access",
                Description = "Write access to API resources",
                Type = ScopeType.Resource,
                Claims = new[] { "scope" }
            },
            new StandardScopeDefinition
            {
                Name = "mrwho.use",
                DisplayName = "MrWho API Usage",
                Description = "Use MrWho API services and features",
                Type = ScopeType.Resource,
                Claims = new[] { "department" }
            }
        };

        foreach (var standardScope in standardScopes)
        {
            await CreateOrUpdateDatabaseScopeAsync(standardScope);
        }
    }

    /// <summary>
    /// Initializes standard identity resources in the database
    /// </summary>
    public async Task InitializeStandardIdentityResourcesAsync()
    {
        var identityResources = new[]
        {
            new StandardIdentityResourceDefinition
            {
                Name = "openid",
                DisplayName = "OpenID",
                Description = "Access to OpenID Connect identity",
                IsRequired = true,
                Claims = new[] { "sub" }
            },
            new StandardIdentityResourceDefinition
            {
                Name = "profile",
                DisplayName = "Profile",
                Description = "Access to profile information",
                Claims = new[] { "name", "family_name", "given_name", "middle_name", "nickname", "preferred_username", "profile", "picture", "website", "gender", "birthdate", "zoneinfo", "locale", "updated_at" }
            },
            new StandardIdentityResourceDefinition
            {
                Name = "email",
                DisplayName = "Email",
                Description = "Access to email address",
                Claims = new[] { "email", "email_verified" }
            },
            new StandardIdentityResourceDefinition
            {
                Name = "roles",
                DisplayName = "Roles",
                Description = "Access to user roles",
                Claims = new[] { "role" }
            },
            new StandardIdentityResourceDefinition
            {
                Name = "phone",
                DisplayName = "Phone",
                Description = "Access to phone number",
                Claims = new[] { "phone_number", "phone_number_verified" }
            },
            new StandardIdentityResourceDefinition
            {
                Name = "address",
                DisplayName = "Address",
                Description = "Access to address information",
                Claims = new[] { "address" }
            }
        };

        foreach (var identityResource in identityResources)
        {
            await CreateOrUpdateIdentityResourceAsync(identityResource);
        }
    }

    private async Task CreateOrUpdateDatabaseScopeAsync(StandardScopeDefinition standardScope)
    {
        var existingScope = await _context.Scopes
            .Include(s => s.Claims)
            .FirstOrDefaultAsync(s => s.Name == standardScope.Name);

        if (existingScope == null)
        {
            var scope = new Scope
            {
                Name = standardScope.Name,
                DisplayName = standardScope.DisplayName,
                Description = standardScope.Description,
                IsEnabled = true,
                IsRequired = standardScope.IsRequired,
                ShowInDiscoveryDocument = true,
                IsStandard = true,
                Type = standardScope.Type,
                CreatedBy = "System"
            };

            _context.Scopes.Add(scope);
            await _context.SaveChangesAsync();

            // Add claims
            foreach (var claimType in standardScope.Claims)
            {
                _context.ScopeClaims.Add(new ScopeClaim
                {
                    ScopeId = scope.Id,
                    ClaimType = claimType
                });
            }

            await _context.SaveChangesAsync();
            _logger.LogInformation("Created standard scope '{ScopeName}' in database", scope.Name);
        }
        else
        {
            // Update existing scope if needed
            var updated = false;

            if (existingScope.DisplayName != standardScope.DisplayName)
            {
                existingScope.DisplayName = standardScope.DisplayName;
                updated = true;
            }

            if (existingScope.Description != standardScope.Description)
            {
                existingScope.Description = standardScope.Description;
                updated = true;
            }

            if (existingScope.IsRequired != standardScope.IsRequired)
            {
                existingScope.IsRequired = standardScope.IsRequired;
                updated = true;
            }

            if (existingScope.Type != standardScope.Type)
            {
                existingScope.Type = standardScope.Type;
                updated = true;
            }

            if (!existingScope.IsStandard)
            {
                existingScope.IsStandard = true;
                updated = true;
            }

            // Ensure standard claims exist but preserve any custom claims added by admins
            var existingClaims = existingScope.Claims.Select(c => c.ClaimType).ToHashSet();
            var requiredClaims = standardScope.Claims.ToHashSet();

            // Add any missing required claims
            var missing = requiredClaims.Except(existingClaims).ToList();
            if (missing.Count > 0)
            {
                foreach (var claimType in missing)
                {
                    _context.ScopeClaims.Add(new ScopeClaim
                    {
                        ScopeId = existingScope.Id,
                        ClaimType = claimType
                    });
                }
                updated = true;
            }

            if (updated)
            {
                existingScope.UpdatedAt = DateTime.UtcNow;
                existingScope.UpdatedBy = "System";
                await _context.SaveChangesAsync();
                _logger.LogInformation("Updated standard scope '{ScopeName}' in database", existingScope.Name);
            }
        }
    }

    private async Task CreateOrUpdateIdentityResourceAsync(StandardIdentityResourceDefinition identityResource)
    {
        var existing = await _context.IdentityResources
            .Include(ir => ir.UserClaims)
            .FirstOrDefaultAsync(ir => ir.Name == identityResource.Name);

        if (existing == null)
        {
            var resource = new IdentityResource
            {
                Name = identityResource.Name,
                DisplayName = identityResource.DisplayName,
                Description = identityResource.Description,
                IsEnabled = true,
                IsRequired = identityResource.IsRequired,
                ShowInDiscoveryDocument = true,
                IsStandard = true,
                CreatedBy = "System"
            };

            _context.IdentityResources.Add(resource);
            await _context.SaveChangesAsync();

            // Add claims
            foreach (var claimType in identityResource.Claims)
            {
                _context.IdentityResourceClaims.Add(new IdentityResourceClaim
                {
                    IdentityResourceId = resource.Id,
                    ClaimType = claimType
                });
            }

            await _context.SaveChangesAsync();
            _logger.LogInformation("Created standard identity resource '{ResourceName}' in database", resource.Name);
        }
        else
        {
            // Update existing identity resource if needed
            var updated = false;

            if (existing.DisplayName != identityResource.DisplayName)
            {
                existing.DisplayName = identityResource.DisplayName;
                updated = true;
            }

            if (existing.Description != identityResource.Description)
            {
                existing.Description = identityResource.Description;
                updated = true;
            }

            if (existing.IsRequired != identityResource.IsRequired)
            {
                existing.IsRequired = identityResource.IsRequired;
                updated = true;
            }

            if (!existing.IsStandard)
            {
                existing.IsStandard = true;
                updated = true;
            }

            // Check if claims need updating
            var existingClaims = existing.UserClaims.Select(c => c.ClaimType).ToHashSet();
            var expectedClaims = identityResource.Claims.ToHashSet();

            if (!existingClaims.SetEquals(expectedClaims))
            {
                _context.IdentityResourceClaims.RemoveRange(existing.UserClaims);
                foreach (var claimType in identityResource.Claims)
                {
                    _context.IdentityResourceClaims.Add(new IdentityResourceClaim
                    {
                        IdentityResourceId = existing.Id,
                        ClaimType = claimType
                    });
                }
                updated = true;
            }

            if (updated)
            {
                existing.UpdatedAt = DateTime.UtcNow;
                existing.UpdatedBy = "System";
                await _context.SaveChangesAsync();
                _logger.LogInformation("Updated standard identity resource '{ResourceName}' in database", existing.Name);
            }
        }
    }

    private class StandardScopeDefinition
    {
        public string Name { get; set; } = string.Empty;
        public string DisplayName { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public bool IsRequired { get; set; } = false;
        public ScopeType Type { get; set; } = ScopeType.Identity;
        public string[] Claims { get; set; } = Array.Empty<string>();
    }

    private class StandardIdentityResourceDefinition
    {
        public string Name { get; set; } = string.Empty;
        public string DisplayName { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public bool IsRequired { get; set; } = false;
        public string[] Claims { get; set; } = Array.Empty<string>();
    }
}