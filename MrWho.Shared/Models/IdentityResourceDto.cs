using System.ComponentModel.DataAnnotations;

namespace MrWho.Shared.Models;

/// <summary>
/// DTO for Identity Resource
/// </summary>
public class IdentityResourceDto
{
    public string Id { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public string? DisplayName { get; set; }
    public string? Description { get; set; }
    public bool IsEnabled { get; set; } = true;
    public bool IsRequired { get; set; } = false;
    public bool IsStandard { get; set; } = false;
    public bool ShowInDiscoveryDocument { get; set; } = true;
    public bool Emphasize { get; set; } = false;
    public DateTime CreatedAt { get; set; }
    public DateTime UpdatedAt { get; set; }
    public string? CreatedBy { get; set; }
    public string? UpdatedBy { get; set; }
    public List<IdentityResourceClaimDto> UserClaims { get; set; } = new();
    public Dictionary<string, string> Properties { get; set; } = new();
}

/// <summary>
/// Request to create a new identity resource
/// </summary>
public class CreateIdentityResourceRequest
{
    [Required]
    [StringLength(200)]
    public string Name { get; set; } = string.Empty;

    [StringLength(200)]
    public string? DisplayName { get; set; }

    [StringLength(1000)]
    public string? Description { get; set; }

    public bool IsEnabled { get; set; } = true;
    public bool IsRequired { get; set; } = false;
    public bool ShowInDiscoveryDocument { get; set; } = true;
    public bool Emphasize { get; set; } = false;

    public List<string> UserClaims { get; set; } = new();
    public Dictionary<string, string> Properties { get; set; } = new();
}

/// <summary>
/// Request to update an existing identity resource
/// </summary>
public class UpdateIdentityResourceRequest
{
    [StringLength(200)]
    public string? DisplayName { get; set; }

    [StringLength(1000)]
    public string? Description { get; set; }

    public bool? IsEnabled { get; set; }
    public bool? IsRequired { get; set; }
    public bool? ShowInDiscoveryDocument { get; set; }
    public bool? Emphasize { get; set; }

    public List<string>? UserClaims { get; set; }
    public Dictionary<string, string>? Properties { get; set; }
}