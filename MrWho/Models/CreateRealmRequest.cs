using System.ComponentModel.DataAnnotations;

namespace MrWho.Models;

/// <summary>
/// DTO for creating/updating realms
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
    public TimeSpan AccessTokenLifetime { get; set; } = TimeSpan.FromMinutes(60);
    public TimeSpan RefreshTokenLifetime { get; set; } = TimeSpan.FromDays(30);
    public TimeSpan AuthorizationCodeLifetime { get; set; } = TimeSpan.FromMinutes(10);
}
