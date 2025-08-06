using Microsoft.EntityFrameworkCore;
using MrWho.Data;
using MrWho.Models;
using MrWho.Shared.Models;
using OpenIddict.Abstractions;

namespace MrWho.Services;

public interface IScopeSeederService
{
    Task InitializeStandardScopesAsync();
    Task SynchronizeAllScopesWithOpenIddictAsync();
    Task RegisterDatabaseScopeWithOpenIddictAsync(Scope scope);
    Task RemoveScopeFromOpenIddictAsync(string scopeName);
}

public class ScopeSeederService : IScopeSeederService
{
    private readonly ApplicationDbContext _context;
    private readonly IOpenIddictScopeManager _scopeManager;
    private readonly ILogger<ScopeSeederService> _logger;

    public ScopeSeederService(
        ApplicationDbContext context, 
        IOpenIddictScopeManager scopeManager,
        ILogger<ScopeSeederService> logger)
    {
        _context = context;
        _scopeManager = scopeManager;
        _logger = logger;
    }

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
            // 1. Create/update scope in our database
            await CreateOrUpdateDatabaseScopeAsync(standardScope);
            
            // 2. Register scope with OpenIddict
            await RegisterScopeWithOpenIddictAsync(standardScope);
        }
    }

    /// <summary>
    /// Synchronizes all enabled scopes from the database with OpenIddict
    /// This ensures that custom scopes created via the admin interface are available to OpenIddict
    /// </summary>
    public async Task SynchronizeAllScopesWithOpenIddictAsync()
    {
        try
        {
            // Get all enabled scopes from the database
            var enabledScopes = await _context.Scopes
                .Include(s => s.Claims)
                .Where(s => s.IsEnabled)
                .ToListAsync();

            _logger.LogInformation("Synchronizing {ScopeCount} enabled scopes with OpenIddict", enabledScopes.Count);

            foreach (var scope in enabledScopes)
            {
                await RegisterDatabaseScopeWithOpenIddictAsync(scope);
            }

            _logger.LogInformation("Successfully synchronized all enabled scopes with OpenIddict");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to synchronize scopes with OpenIddict");
            throw;
        }
    }

    /// <summary>
    /// Registers or updates a single database scope with OpenIddict
    /// Used for both batch synchronization and individual scope updates
    /// </summary>
    public async Task RegisterDatabaseScopeWithOpenIddictAsync(Scope scope)
    {
        try
        {
            // Check if scope already exists in OpenIddict
            var existingOpenIddictScope = await _scopeManager.FindByNameAsync(scope.Name);
            
            var descriptor = new OpenIddictScopeDescriptor
            {
                Name = scope.Name,
                DisplayName = scope.DisplayName ?? scope.Name,
                Description = scope.Description
            };

            // Add claims (resources for the scope)
            foreach (var claim in scope.Claims)
            {
                descriptor.Resources.Add(claim.ClaimType);
            }

            if (existingOpenIddictScope != null)
            {
                // Update existing scope
                await _scopeManager.UpdateAsync(existingOpenIddictScope, descriptor);
                _logger.LogDebug("Updated scope '{ScopeName}' in OpenIddict", scope.Name);
            }
            else
            {
                // Create new scope in OpenIddict
                await _scopeManager.CreateAsync(descriptor);
                _logger.LogDebug("Created scope '{ScopeName}' in OpenIddict", scope.Name);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to register scope '{ScopeName}' with OpenIddict", scope.Name);
            throw;
        }
    }

    /// <summary>
    /// Removes a scope from OpenIddict (used when scopes are deleted or disabled)
    /// </summary>
    public async Task RemoveScopeFromOpenIddictAsync(string scopeName)
    {
        try
        {
            var existingScope = await _scopeManager.FindByNameAsync(scopeName);
            if (existingScope != null)
            {
                await _scopeManager.DeleteAsync(existingScope);
                _logger.LogInformation("Removed scope '{ScopeName}' from OpenIddict", scopeName);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to remove scope '{ScopeName}' from OpenIddict", scopeName);
            throw;
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

            // Check if claims need updating
            var existingClaims = existingScope.Claims.Select(c => c.ClaimType).ToHashSet();
            var expectedClaims = standardScope.Claims.ToHashSet();

            if (!existingClaims.SetEquals(expectedClaims))
            {
                _context.ScopeClaims.RemoveRange(existingScope.Claims);
                foreach (var claimType in standardScope.Claims)
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

    private async Task RegisterScopeWithOpenIddictAsync(StandardScopeDefinition standardScope)
    {
        try
        {
            // Check if scope already exists in OpenIddict
            var existingOpenIddictScope = await _scopeManager.FindByNameAsync(standardScope.Name);
            
            if (existingOpenIddictScope != null)
            {
                // Update existing scope
                var descriptor = new OpenIddictScopeDescriptor
                {
                    Name = standardScope.Name,
                    DisplayName = standardScope.DisplayName,
                    Description = standardScope.Description
                };

                // Add claims (resources for the scope)
                foreach (var claim in standardScope.Claims)
                {
                    descriptor.Resources.Add(claim);
                }

                await _scopeManager.UpdateAsync(existingOpenIddictScope, descriptor);
                _logger.LogInformation("Updated scope '{ScopeName}' in OpenIddict", standardScope.Name);
            }
            else
            {
                // Create new scope in OpenIddict
                var descriptor = new OpenIddictScopeDescriptor
                {
                    Name = standardScope.Name,
                    DisplayName = standardScope.DisplayName,
                    Description = standardScope.Description
                };

                // Add claims (resources for the scope)
                foreach (var claim in standardScope.Claims)
                {
                    descriptor.Resources.Add(claim);
                }

                await _scopeManager.CreateAsync(descriptor);
                _logger.LogInformation("Created scope '{ScopeName}' in OpenIddict", standardScope.Name);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to register scope '{ScopeName}' with OpenIddict", standardScope.Name);
            throw;
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
}