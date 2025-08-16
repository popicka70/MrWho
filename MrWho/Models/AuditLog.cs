using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace MrWho.Models;

public enum AuditAction
{
    Added,
    Modified,
    Deleted
}

/// <summary>
/// Generic audit log entry capturing entity changes.
/// </summary>
public class AuditLog
{
    [Key]
    public string Id { get; set; } = Guid.NewGuid().ToString();

    /// <summary>
    /// When the change occurred (UTC)
    /// </summary>
    public DateTime OccurredAt { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// User performing the change (subject/identifier)
    /// </summary>
    [StringLength(200)]
    public string? UserId { get; set; }

    /// <summary>
    /// Display/user name for convenience
    /// </summary>
    [StringLength(256)]
    public string? UserName { get; set; }

    /// <summary>
    /// IP address of the request causing the change
    /// </summary>
    [StringLength(64)]
    public string? IpAddress { get; set; }

    /// <summary>
    /// CLR entity type name
    /// </summary>
    [Required]
    [StringLength(256)]
    public string EntityType { get; set; } = string.Empty;

    /// <summary>
    /// Primary key value(s) string representation (for composite keys, '|' separated)
    /// </summary>
    [Required]
    [StringLength(512)]
    public string EntityId { get; set; } = string.Empty;

    /// <summary>
    /// Change type
    /// </summary>
    [Required]
    [StringLength(50)]
    public string Action { get; set; } = AuditAction.Modified.ToString();

    /// <summary>
    /// JSON representation of property-level changes
    /// [{"Property":"Name","Old":"old","New":"new"}, ...]
    /// </summary>
    public string? Changes { get; set; }

    /// <summary>
    /// Optional context fields (realm/client) if known
    /// </summary>
    [StringLength(200)]
    public string? RealmId { get; set; }

    [StringLength(200)]
    public string? ClientId { get; set; }
}
