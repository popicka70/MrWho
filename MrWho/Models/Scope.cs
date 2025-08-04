using System.ComponentModel.DataAnnotations;
using MrWho.Shared.Models;

namespace MrWho.Models;

/// <summary>
/// OIDC Scope definition
/// </summary>
public class Scope
{
    [Key]
    public string Id { get; set; } = Guid.NewGuid().ToString();

    [Required]
    [StringLength(100)]
    public string Name { get; set; } = string.Empty;

    [StringLength(200)]
    public string? DisplayName { get; set; }

    [StringLength(500)]
    public string? Description { get; set; }

    public bool IsEnabled { get; set; } = true;

    public bool IsRequired { get; set; } = false;

    public bool ShowInDiscoveryDocument { get; set; } = true;

    public bool IsStandard { get; set; } = false;

    public ScopeType Type { get; set; } = ScopeType.Identity;

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    public DateTime? UpdatedAt { get; set; }

    public string? CreatedBy { get; set; }

    public string? UpdatedBy { get; set; }

    /// <summary>
    /// Claims that are included in this scope
    /// </summary>
    public virtual ICollection<ScopeClaim> Claims { get; set; } = new List<ScopeClaim>();
}