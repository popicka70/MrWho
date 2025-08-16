using System.ComponentModel.DataAnnotations;

namespace MrWho.Shared.Models;

public class TokenStatisticsOverviewDto
{
    public long TotalTokens { get; set; }
    public long AccessTokens { get; set; }
    public long RefreshTokens { get; set; }
    public long AuthorizationCodes { get; set; }
    public long DeviceCodes { get; set; }

    public long ActiveAccessTokens { get; set; }
    public long ActiveRefreshTokens { get; set; }

    public long ExpiredTokens { get; set; }
    public long RevokedTokens { get; set; }
    public long RedeemedTokens { get; set; }

    public long IssuedLast24H { get; set; }
    public long IssuedLast7D { get; set; }
}

public class TokenClientStatDto
{
    [StringLength(200)]
    public string ClientId { get; set; } = string.Empty;
    [StringLength(200)]
    public string? ClientName { get; set; }

    public long AccessTokens { get; set; }
    public long RefreshTokens { get; set; }
    public long ActiveAccessTokens { get; set; }
    public long ActiveRefreshTokens { get; set; }
    public long RevokedTokens { get; set; }
}

public class TokenTimeSeriesPointDto
{
    public DateOnly Date { get; set; }
    public long AccessTokens { get; set; }
    public long RefreshTokens { get; set; }
    public long AuthorizationCodes { get; set; }
    public long DeviceCodes { get; set; }
}
