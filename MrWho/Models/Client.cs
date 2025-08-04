using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using MrWho.Shared;

namespace MrWho.Models;

/// <summary>
/// Represents an OIDC client configuration
/// </summary>
public class Client
{
    [Key]
    public string Id { get; set; } = Guid.NewGuid().ToString();

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
    public bool IsEnabled { get; set; } = true;

    // Client type and flow settings
    public ClientType ClientType { get; set; } = ClientType.Confidential;
    public bool AllowAuthorizationCodeFlow { get; set; } = true;
    public bool AllowClientCredentialsFlow { get; set; } = false;
    public bool AllowPasswordFlow { get; set; } = false;
    public bool AllowRefreshTokenFlow { get; set; } = true;
    public bool RequirePkce { get; set; } = true;
    public bool RequireClientSecret { get; set; } = true;

    // Token lifetimes (null means use realm defaults)
    public TimeSpan? AccessTokenLifetime { get; set; }
    public TimeSpan? RefreshTokenLifetime { get; set; }
    public TimeSpan? AuthorizationCodeLifetime { get; set; }

    // Audit fields
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;
    public string? CreatedBy { get; set; }
    public string? UpdatedBy { get; set; }

    // Realm relationship
    [Required]
    public string RealmId { get; set; } = string.Empty;
    
    [ForeignKey(nameof(RealmId))]
    public virtual Realm Realm { get; set; } = null!;

    // Navigation properties
    public virtual ICollection<ClientRedirectUri> RedirectUris { get; set; } = new List<ClientRedirectUri>();
    public virtual ICollection<ClientPostLogoutUri> PostLogoutUris { get; set; } = new List<ClientPostLogoutUri>();
    public virtual ICollection<ClientScope> Scopes { get; set; } = new List<ClientScope>();
    public virtual ICollection<ClientPermission> Permissions { get; set; } = new List<ClientPermission>();
}
