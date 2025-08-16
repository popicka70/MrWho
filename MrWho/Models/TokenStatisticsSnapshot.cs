using System.ComponentModel.DataAnnotations;

namespace MrWho.Models;

public class TokenStatisticsSnapshot
{
    [Key]
    public string Id { get; set; } = Guid.NewGuid().ToString();

    // e.g., "hourly" or "daily"
    [Required]
    [StringLength(20)]
    public string Granularity { get; set; } = "daily";

    // Inclusive start and exclusive end (UTC)
    public DateTimeOffset PeriodStartUtc { get; set; }
    public DateTimeOffset PeriodEndUtc { get; set; }

    // Issued within period
    public long AccessTokensIssued { get; set; }
    public long RefreshTokensIssued { get; set; }
    public long AuthorizationCodesIssued { get; set; }
    public long DeviceCodesIssued { get; set; }

    // State at end of period (active/expired/revoked as of PeriodEndUtc)
    public long ActiveAccessTokensEnd { get; set; }
    public long ActiveRefreshTokensEnd { get; set; }
    public long ExpiredTokensEnd { get; set; }
    public long RevokedTokensEnd { get; set; }

    public DateTimeOffset CreatedAtUtc { get; set; } = DateTimeOffset.UtcNow;
}
