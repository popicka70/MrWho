using Microsoft.EntityFrameworkCore;
using MrWho.Data;
using MrWho.Models;
using MrWho.Shared.Models;

namespace MrWho.Services;

public interface IScopeSeederService
{
    Task InitializeStandardScopesAsync();
}

public class ScopeSeederService : IScopeSeederService
{
    private readonly ApplicationDbContext _context;
    private readonly ILogger<ScopeSeederService> _logger;

    public ScopeSeederService(ApplicationDbContext context, ILogger<ScopeSeederService> logger)
    {
        _context = context;
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
            }
        };

        foreach (var standardScope in standardScopes)
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
                _logger.LogInformation("Created standard scope '{ScopeName}'", standardScope.Name);
            }
            else
            {
                // Update existing standard scope if needed
                var needsUpdate = false;

                if (existingScope.DisplayName != standardScope.DisplayName)
                {
                    existingScope.DisplayName = standardScope.DisplayName;
                    needsUpdate = true;
                }

                if (existingScope.Description != standardScope.Description)
                {
                    existingScope.Description = standardScope.Description;
                    needsUpdate = true;
                }

                if (existingScope.IsRequired != standardScope.IsRequired)
                {
                    existingScope.IsRequired = standardScope.IsRequired;
                    needsUpdate = true;
                }

                if (existingScope.Type != standardScope.Type)
                {
                    existingScope.Type = standardScope.Type;
                    needsUpdate = true;
                }

                if (!existingScope.IsStandard)
                {
                    existingScope.IsStandard = true;
                    needsUpdate = true;
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
                    needsUpdate = true;
                }

                if (needsUpdate)
                {
                    existingScope.UpdatedAt = DateTime.UtcNow;
                    existingScope.UpdatedBy = "System";
                    await _context.SaveChangesAsync();
                    _logger.LogInformation("Updated standard scope '{ScopeName}'", standardScope.Name);
                }
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