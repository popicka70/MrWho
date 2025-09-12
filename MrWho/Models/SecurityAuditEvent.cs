using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace MrWho.Models;

/// <summary>
/// Append-only security/audit event with integrity hash chaining.
/// </summary>
public class SecurityAuditEvent
{
    [Key]
    [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
    public long Id { get; set; }

    [Required]
    public DateTime TimestampUtc { get; set; } = DateTime.UtcNow;

    [Required, StringLength(100)]
    public string Category { get; set; } = string.Empty; // e.g. auth.security

    [Required, StringLength(150)]
    public string EventType { get; set; } = string.Empty; // e.g. jar.validation_failed

    [StringLength(20)]
    public string? Level { get; set; } // info|warn|error

    [StringLength(200)]
    public string? ActorUserId { get; set; }

    [StringLength(200)]
    public string? ActorClientId { get; set; }

    [StringLength(64)]
    public string? IpAddress { get; set; }

    public string? DataJson { get; set; } // optional structured data

    [StringLength(128)]
    public string? PrevHash { get; set; }

    [StringLength(128)]
    public string Hash { get; set; } = string.Empty; // SHA256(current payload + prev)
}
