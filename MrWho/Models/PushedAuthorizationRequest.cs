using System.ComponentModel.DataAnnotations;
using Microsoft.EntityFrameworkCore; // added for [Index]

namespace MrWho.Models;

/// <summary>
/// Stored pushed authorization request parameters (PAR - RFC 9126)
/// </summary>
[PrimaryKey(nameof(Id))]
[Index(nameof(ClientId), nameof(ParametersHash))]
public class PushedAuthorizationRequest
{
    [Key]
    public string Id { get; set; } = Guid.NewGuid().ToString("n");

    /// <summary>
    /// Public request_uri value returned to client (urn:ietf:params:oauth:request_uri:{Id})
    /// </summary>
    [MaxLength(300)]
    public string RequestUri { get; set; } = string.Empty;

    [Required]
    [MaxLength(200)]
    public string ClientId { get; set; } = string.Empty;

    /// <summary>
    /// Authorization request parameters (JSON serialized key/value pairs)
    /// </summary>
    public string ParametersJson { get; set; } = string.Empty;

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime ExpiresAt { get; set; } = DateTime.UtcNow.AddSeconds(90);
    public DateTime? ConsumedAt { get; set; }

    /// <summary>
    /// Optional hash of ParametersJson or raw request JWT (stable hash for replay detection)
    /// </summary>
    [MaxLength(128)]
    public string? ParametersHash { get; set; }
}
