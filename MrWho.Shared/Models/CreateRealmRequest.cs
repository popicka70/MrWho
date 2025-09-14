using System.ComponentModel.DataAnnotations;
using MrWho.Shared;

namespace MrWho.Shared.Models;

/// <summary>
/// Request for creating/updating realms
/// </summary>
public class CreateRealmRequest
{
    [Required]
    [StringLength(200)]
    public string Name { get; set; } = string.Empty;

    [StringLength(500)]
    public string? Description { get; set; }

    [StringLength(500)]
    public string? DisplayName { get; set; }

    public bool IsEnabled { get; set; } = true;
    public TimeSpan AccessTokenLifetime { get; set; } = MrWhoConstants.TokenLifetimes.AccessToken;
    public TimeSpan RefreshTokenLifetime { get; set; } = MrWhoConstants.TokenLifetimes.RefreshToken;
    public TimeSpan AuthorizationCodeLifetime { get; set; } = MrWhoConstants.TokenLifetimes.AuthorizationCode;
}
