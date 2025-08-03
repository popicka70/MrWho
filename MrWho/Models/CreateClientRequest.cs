using System.ComponentModel.DataAnnotations;

namespace MrWho.Models;

/// <summary>
/// Request for creating clients
/// </summary>
public class CreateClientRequest
{
    [Required]
    [StringLength(200)]
    public string ClientId { get; set; } = string.Empty;

    [StringLength(500)]
    public string? ClientSecret { get; set; }

    [Required]
    [StringLength(200)]
    public string Name { get; set; } = string.Empty;

    [StringLength(500)]
    public string? Description { get; set; }

    [Required]
    public string RealmId { get; set; } = string.Empty;

    public bool IsEnabled { get; set; } = true;
    public ClientType ClientType { get; set; } = ClientType.Confidential;
    public bool AllowAuthorizationCodeFlow { get; set; } = true;
    public bool AllowClientCredentialsFlow { get; set; } = false;
    public bool AllowPasswordFlow { get; set; } = false;
    public bool AllowRefreshTokenFlow { get; set; } = true;
    public bool RequirePkce { get; set; } = true;
    public bool RequireClientSecret { get; set; } = true;

    public TimeSpan? AccessTokenLifetime { get; set; }
    public TimeSpan? RefreshTokenLifetime { get; set; }
    public TimeSpan? AuthorizationCodeLifetime { get; set; }

    public List<string> RedirectUris { get; set; } = new();
    public List<string> PostLogoutUris { get; set; } = new();
    public List<string> Scopes { get; set; } = new();
    public List<string> Permissions { get; set; } = new();
}
