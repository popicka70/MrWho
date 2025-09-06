using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace MrWho.Models;

/// <summary>
/// Stores short opaque IDs that map to long returnUrl/authorize URLs (e.g., PAR request_uri flows).
/// Enables cleaner URLs and supports horizontal scaling when stored in DB.
/// </summary>
[Table("ReturnUrlEntries")]
public class ReturnUrlEntry
{
    [Key]
    [MaxLength(64)]
    public string Id { get; set; } = default!; // opaque key

    [Required]
    [MaxLength(4000)]
    public string Url { get; set; } = default!; // full returnUrl/authorize URL

    [MaxLength(200)]
    public string? ClientId { get; set; }

    [Required]
    public DateTime CreatedAt { get; set; }

    [Required]
    public DateTime ExpiresAt { get; set; }
}
