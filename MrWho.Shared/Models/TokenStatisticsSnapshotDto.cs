using System.Text.Json.Serialization;

namespace MrWho.Shared.Models;

public class TokenStatisticsSnapshotDto
{
    public string Id { get; set; } = string.Empty;
    public string Granularity { get; set; } = string.Empty;
    public DateTimeOffset PeriodStartUtc { get; set; }
    public DateTimeOffset PeriodEndUtc { get; set; }

    public long AccessTokensIssued { get; set; }
    public long RefreshTokensIssued { get; set; }
    public long AuthorizationCodesIssued { get; set; }
    public long DeviceCodesIssued { get; set; }

    public long ActiveAccessTokensEnd { get; set; }
    public long ActiveRefreshTokensEnd { get; set; }
    public long ExpiredTokensEnd { get; set; }
    public long RevokedTokensEnd { get; set; }

    public DateTimeOffset CreatedAtUtc { get; set; }

    // Helper properties for UI binding (not serialized)
    [JsonIgnore]
    public DateTime PeriodStart => PeriodStartUtc.UtcDateTime;

    [JsonIgnore]
    public DateTime PeriodEnd => PeriodEndUtc.UtcDateTime;
}
