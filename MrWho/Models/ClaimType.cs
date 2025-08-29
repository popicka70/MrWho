using System.ComponentModel.DataAnnotations;

namespace MrWho.Models;

/// <summary>
/// Canonical claim type registry entry
/// </summary>
public class ClaimType
{
    [Key]
    public string Id { get; set; } = Guid.NewGuid().ToString();

    /// <summary>
    /// Technical type name, e.g. "given_name"
    /// </summary>
    [Required]
    [StringLength(256)]
    public string Type { get; set; } = string.Empty;

    /// <summary>
    /// Human friendly display name
    /// </summary>
    [StringLength(256)]
    public string DisplayName { get; set; } = string.Empty;

    /// <summary>
    /// Detailed description / help text
    /// </summary>
    [StringLength(2000)]
    public string? Description { get; set; }

    /// <summary>
    /// Optional category/grouping (profile, business, system, etc.)
    /// </summary>
    [StringLength(100)]
    public string? Category { get; set; }

    public bool IsStandard { get; set; } = false;
    public bool IsEnabled { get; set; } = true;
    public bool IsObsolete { get; set; } = false;
    public int? SortOrder { get; set; }

    // Audit
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;
    public string? CreatedBy { get; set; }
    public string? UpdatedBy { get; set; }
}
