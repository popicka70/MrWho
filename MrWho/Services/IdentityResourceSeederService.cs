using Microsoft.EntityFrameworkCore;
using MrWho.Data;
using MrWho.Models;

namespace MrWho.Services;

public interface IIdentityResourceSeederService
{
    Task SeedStandardIdentityResourcesAsync();
}

public class IdentityResourceSeederService : IIdentityResourceSeederService
{
    private readonly ApplicationDbContext _context;
    private readonly ILogger<IdentityResourceSeederService> _logger;

    public IdentityResourceSeederService(
        ApplicationDbContext context,
        ILogger<IdentityResourceSeederService> logger)
    {
        _context = context;
        _logger = logger;
    }

    public async Task SeedStandardIdentityResourcesAsync()
    {
        var standardIdentityResources = GetStandardIdentityResourceDefinitions();

        foreach (var standardIdentityResource in standardIdentityResources)
        {
            var existingIdentityResource = await _context.IdentityResources
                .Include(ir => ir.UserClaims)
                .Include(ir => ir.Properties)
                .FirstOrDefaultAsync(ir => ir.Name == standardIdentityResource.Name);

            if (existingIdentityResource == null)
            {
                var identityResource = new IdentityResource
                {
                    Name = standardIdentityResource.Name,
                    DisplayName = standardIdentityResource.DisplayName,
                    Description = standardIdentityResource.Description,
                    IsEnabled = true,
                    IsRequired = standardIdentityResource.IsRequired,
                    IsStandard = true,
                    ShowInDiscoveryDocument = standardIdentityResource.ShowInDiscoveryDocument,
                    Emphasize = standardIdentityResource.Emphasize,
                    CreatedBy = "System"
                };

                _context.IdentityResources.Add(identityResource);
                await _context.SaveChangesAsync();

                // Add user claims
                foreach (var claim in standardIdentityResource.UserClaims)
                {
                    _context.IdentityResourceClaims.Add(new IdentityResourceClaim
                    {
                        IdentityResourceId = identityResource.Id,
                        ClaimType = claim
                    });
                }

                // Add properties
                foreach (var property in standardIdentityResource.Properties)
                {
                    _context.IdentityResourceProperties.Add(new IdentityResourceProperty
                    {
                        IdentityResourceId = identityResource.Id,
                        Key = property.Key,
                        Value = property.Value
                    });
                }

                await _context.SaveChangesAsync();
                _logger.LogInformation("Created standard identity resource '{IdentityResourceName}'", standardIdentityResource.Name);
            }
            else
            {
                // Update existing standard identity resource if needed
                var needsUpdate = false;

                if (existingIdentityResource.DisplayName != standardIdentityResource.DisplayName)
                {
                    existingIdentityResource.DisplayName = standardIdentityResource.DisplayName;
                    needsUpdate = true;
                }

                if (existingIdentityResource.Description != standardIdentityResource.Description)
                {
                    existingIdentityResource.Description = standardIdentityResource.Description;
                    needsUpdate = true;
                }

                if (!existingIdentityResource.IsStandard)
                {
                    existingIdentityResource.IsStandard = true;
                    needsUpdate = true;
                }

                if (existingIdentityResource.IsRequired != standardIdentityResource.IsRequired)
                {
                    existingIdentityResource.IsRequired = standardIdentityResource.IsRequired;
                    needsUpdate = true;
                }

                if (existingIdentityResource.ShowInDiscoveryDocument != standardIdentityResource.ShowInDiscoveryDocument)
                {
                    existingIdentityResource.ShowInDiscoveryDocument = standardIdentityResource.ShowInDiscoveryDocument;
                    needsUpdate = true;
                }

                if (existingIdentityResource.Emphasize != standardIdentityResource.Emphasize)
                {
                    existingIdentityResource.Emphasize = standardIdentityResource.Emphasize;
                    needsUpdate = true;
                }

                // Check if user claims need updating
                var existingClaims = existingIdentityResource.UserClaims.Select(c => c.ClaimType).ToHashSet();
                var expectedClaims = standardIdentityResource.UserClaims.ToHashSet();

                if (!existingClaims.SetEquals(expectedClaims))
                {
                    _context.IdentityResourceClaims.RemoveRange(existingIdentityResource.UserClaims);
                    foreach (var claim in standardIdentityResource.UserClaims)
                    {
                        _context.IdentityResourceClaims.Add(new IdentityResourceClaim
                        {
                            IdentityResourceId = existingIdentityResource.Id,
                            ClaimType = claim
                        });
                    }
                    needsUpdate = true;
                }

                // Check if properties need updating
                var existingProperties = existingIdentityResource.Properties.ToDictionary(p => p.Key, p => p.Value);
                var expectedProperties = standardIdentityResource.Properties;

                if (!existingProperties.SequenceEqual(expectedProperties))
                {
                    _context.IdentityResourceProperties.RemoveRange(existingIdentityResource.Properties);
                    foreach (var property in standardIdentityResource.Properties)
                    {
                        _context.IdentityResourceProperties.Add(new IdentityResourceProperty
                        {
                            IdentityResourceId = existingIdentityResource.Id,
                            Key = property.Key,
                            Value = property.Value
                        });
                    }
                    needsUpdate = true;
                }

                if (needsUpdate)
                {
                    existingIdentityResource.UpdatedAt = DateTime.UtcNow;
                    existingIdentityResource.UpdatedBy = "System";
                    await _context.SaveChangesAsync();
                    _logger.LogInformation("Updated standard identity resource '{IdentityResourceName}'", standardIdentityResource.Name);
                }
            }
        }
    }

    private List<StandardIdentityResourceDefinition> GetStandardIdentityResourceDefinitions()
    {
        return new List<StandardIdentityResourceDefinition>
        {
            new StandardIdentityResourceDefinition
            {
                Name = "openid",
                DisplayName = "OpenID",
                Description = "Subject identifier for the user (sub claim)",
                IsRequired = true,
                ShowInDiscoveryDocument = true,
                Emphasize = false,
                UserClaims = new[] { "sub" },
                Properties = new Dictionary<string, string>()
            },
            new StandardIdentityResourceDefinition
            {
                Name = "profile",
                DisplayName = "User Profile",
                Description = "User profile information (name, family name, given name, etc.)",
                IsRequired = false,
                ShowInDiscoveryDocument = true,
                Emphasize = true,
                UserClaims = new[]
                {
                    "name",
                    "given_name",
                    "family_name",
                    "middle_name",
                    "nickname",
                    "preferred_username",
                    "profile",
                    "picture",
                    "website",
                    "gender",
                    "birthdate",
                    "zoneinfo",
                    "locale",
                    "updated_at"
                },
                Properties = new Dictionary<string, string>()
            },
            new StandardIdentityResourceDefinition
            {
                Name = "email",
                DisplayName = "Email",
                Description = "Email address",
                IsRequired = false,
                ShowInDiscoveryDocument = true,
                Emphasize = true,
                UserClaims = new[] { "email", "email_verified" },
                Properties = new Dictionary<string, string>()
            },
            new StandardIdentityResourceDefinition
            {
                Name = "address",
                DisplayName = "Address",
                Description = "Address information",
                IsRequired = false,
                ShowInDiscoveryDocument = true,
                Emphasize = false,
                UserClaims = new[] { "address" },
                Properties = new Dictionary<string, string>()
            },
            new StandardIdentityResourceDefinition
            {
                Name = "phone",
                DisplayName = "Phone",
                Description = "Phone number",
                IsRequired = false,
                ShowInDiscoveryDocument = true,
                Emphasize = false,
                UserClaims = new[] { "phone_number", "phone_number_verified" },
                Properties = new Dictionary<string, string>()
            },
            new StandardIdentityResourceDefinition
            {
                Name = "roles",
                DisplayName = "Roles",
                Description = "User roles and permissions",
                IsRequired = false,
                ShowInDiscoveryDocument = true,
                Emphasize = false,
                UserClaims = new[] { "role" },
                Properties = new Dictionary<string, string>()
            }
        };
    }

    private class StandardIdentityResourceDefinition
    {
        public string Name { get; set; } = string.Empty;
        public string DisplayName { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public bool IsRequired { get; set; } = false;
        public bool ShowInDiscoveryDocument { get; set; } = true;
        public bool Emphasize { get; set; } = false;
        public string[] UserClaims { get; set; } = Array.Empty<string>();
        public Dictionary<string, string> Properties { get; set; } = new();
    }
}
