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