using System.ComponentModel.DataAnnotations;

namespace MrWho.Models;

/// <summary>
/// Represents an OIDC identity resource (user claims that can be requested)
/// </summary>
public class IdentityResource
{
    [Key]
    public string Id { get; set; } = Guid.NewGuid().ToString();

    [Required]
    [StringLength(200)]
    public string Name { get; set; } = string.Empty;

    [StringLength(200)]
    public string? DisplayName { get; set; }

    [StringLength(1000)]
    public string? Description { get; set; }

    public bool IsEnabled { get; set; } = true;

    public bool IsRequired { get; set; } = false;

    public bool IsStandard { get; set; } = false;

    public bool ShowInDiscoveryDocument { get; set; } = true;

    public bool Emphasize { get; set; } = false;

    // Audit fields
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;
    public string? CreatedBy { get; set; }
    public string? UpdatedBy { get; set; }

    // Navigation properties
    public virtual ICollection<IdentityResourceClaim> UserClaims { get; set; } = new List<IdentityResourceClaim>();
    public virtual ICollection<IdentityResourceProperty> Properties { get; set; } = new List<IdentityResourceProperty>();
}

/// <summary>
/// Claims that are included in this identity resource
/// </summary>
public class IdentityResourceClaim
{
    [Key]
    public string Id { get; set; } = Guid.NewGuid().ToString();

    [Required]
    public string IdentityResourceId { get; set; } = string.Empty;

    [Required]
    [StringLength(200)]
    public string ClaimType { get; set; } = string.Empty;

    // Navigation properties
    public virtual IdentityResource IdentityResource { get; set; } = null!;
}

/// <summary>
/// Additional properties for identity resources
/// </summary>
public class IdentityResourceProperty
{
    [Key]
    public string Id { get; set; } = Guid.NewGuid().ToString();

    [Required]
    public string IdentityResourceId { get; set; } = string.Empty;

    [Required]
    [StringLength(250)]
    public string Key { get; set; } = string.Empty;

    [Required]
    [StringLength(2000)]
    public string Value { get; set; } = string.Empty;

    // Navigation properties
    public virtual IdentityResource IdentityResource { get; set; } = null!;
}