using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace MrWho.Models;

/// <summary>
/// Represents a device authorization flow transaction (RFC 8628) managed internally (custom implementation).
/// </summary>
public class DeviceAuthorization
{
    [Key]
    public string Id { get; set; } = Guid.NewGuid().ToString();

    [Required, MaxLength(128)]
    public string DeviceCode { get; set; } = string.Empty; // opaque secret (returned to device)

    [Required, MaxLength(32)]
    public string UserCode { get; set; } = string.Empty; // human friendly (entered by user)

    [Required, MaxLength(200)]
    public string ClientId { get; set; } = string.Empty;

    [MaxLength(4000)]
    public string? Scope { get; set; } // space delimited

    [MaxLength(100)]
    public string? Subject { get; set; } // user id once approved

    [MaxLength(32)]
    public string Status { get; set; } = DeviceAuthorizationStatus.Pending; // Pending/Approved/Denied/Expired/Consumed

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime ExpiresAt { get; set; } = DateTime.UtcNow.AddMinutes(10);
    public DateTime? ApprovedAt { get; set; }
    public DateTime? DeniedAt { get; set; }
    public DateTime? ConsumedAt { get; set; }

    public int PollingIntervalSeconds { get; set; } = 5; // default
    public DateTime? LastPolledAt { get; set; }

    [MaxLength(64)] public string? VerificationIp { get; set; }
    [MaxLength(512)] public string? VerificationUserAgent { get; set; }

    [MaxLength(2000)] public string? MetadataJson { get; set; }
}

public static class DeviceAuthorizationStatus
{
    public const string Pending = "pending";
    public const string Approved = "approved";
    public const string Denied = "denied";
    public const string Expired = "expired";
    public const string Consumed = "consumed";
}
