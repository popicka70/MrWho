using MrWho.Shared;

namespace MrWho.Shared.Models;

/// <summary>
/// DTO for realm data
/// </summary>
public class RealmDto
{
    public string Id { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public string? Description { get; set; }
    public bool IsEnabled { get; set; } = true;
    public string? DisplayName { get; set; }
    public TimeSpan AccessTokenLifetime { get; set; } = MrWhoConstants.TokenLifetimes.AccessToken;
    public TimeSpan RefreshTokenLifetime { get; set; } = MrWhoConstants.TokenLifetimes.RefreshToken;
    public TimeSpan AuthorizationCodeLifetime { get; set; } = MrWhoConstants.TokenLifetimes.AuthorizationCode;
    public DateTime CreatedAt { get; set; }
    public DateTime UpdatedAt { get; set; }
    public string? CreatedBy { get; set; }
    public string? UpdatedBy { get; set; }
    public int ClientCount { get; set; }
}