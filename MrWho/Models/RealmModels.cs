using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace MrWho.Models;

/// <summary>
/// Represents a logical grouping/namespace for OIDC clients
/// </summary>
public class Realm
{
    [Key]
    public string Id { get; set; } = Guid.NewGuid().ToString();

    [Required]
    [StringLength(200)]
    public string Name { get; set; } = string.Empty;

    [StringLength(500)]
    public string? Description { get; set; }

    [Required]
    public bool IsEnabled { get; set; } = true;

    [StringLength(500)]
    public string? DisplayName { get; set; }

    // Security settings
    public TimeSpan AccessTokenLifetime { get; set; } = TimeSpan.FromMinutes(60);
    public TimeSpan RefreshTokenLifetime { get; set; } = TimeSpan.FromDays(30);
    public TimeSpan AuthorizationCodeLifetime { get; set; } = TimeSpan.FromMinutes(10);

    // Audit fields
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;
    public string? CreatedBy { get; set; }
    public string? UpdatedBy { get; set; }

    // Navigation properties
    public virtual ICollection<Client> Clients { get; set; } = new List<Client>();
}

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

/// <summary>
/// Client redirect URIs
/// </summary>
public class ClientRedirectUri
{
    [Key]
    public string Id { get; set; } = Guid.NewGuid().ToString();

    [Required]
    [StringLength(2000)]
    public string Uri { get; set; } = string.Empty;

    [Required]
    public string ClientId { get; set; } = string.Empty;

    [ForeignKey(nameof(ClientId))]
    public virtual Client Client { get; set; } = null!;
}

/// <summary>
/// Client post-logout redirect URIs
/// </summary>
public class ClientPostLogoutUri
{
    [Key]
    public string Id { get; set; } = Guid.NewGuid().ToString();

    [Required]
    [StringLength(2000)]
    public string Uri { get; set; } = string.Empty;

    [Required]
    public string ClientId { get; set; } = string.Empty;

    [ForeignKey(nameof(ClientId))]
    public virtual Client Client { get; set; } = null!;
}

/// <summary>
/// Client allowed scopes
/// </summary>
public class ClientScope
{
    [Key]
    public string Id { get; set; } = Guid.NewGuid().ToString();

    [Required]
    [StringLength(200)]
    public string Scope { get; set; } = string.Empty;

    [Required]
    public string ClientId { get; set; } = string.Empty;

    [ForeignKey(nameof(ClientId))]
    public virtual Client Client { get; set; } = null!;
}

/// <summary>
/// Client OpenIddict permissions
/// </summary>
public class ClientPermission
{
    [Key]
    public string Id { get; set; } = Guid.NewGuid().ToString();

    [Required]
    [StringLength(200)]
    public string Permission { get; set; } = string.Empty;

    [Required]
    public string ClientId { get; set; } = string.Empty;

    [ForeignKey(nameof(ClientId))]
    public virtual Client Client { get; set; } = null!;
}

/// <summary>
/// Client types
/// </summary>
public enum ClientType
{
    /// <summary>
    /// Confidential client (can store secrets securely)
    /// </summary>
    Confidential = 0,
    
    /// <summary>
    /// Public client (cannot store secrets securely, e.g., SPAs, mobile apps)
    /// </summary>
    Public = 1,
    
    /// <summary>
    /// Machine-to-machine client (service accounts)
    /// </summary>
    Machine = 2
}

// DTOs for API operations

/// <summary>
/// DTO for realm creation/update
/// </summary>
public class RealmDto
{
    public string Id { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public string? Description { get; set; }
    public bool IsEnabled { get; set; } = true;
    public string? DisplayName { get; set; }
    public TimeSpan AccessTokenLifetime { get; set; } = TimeSpan.FromMinutes(60);
    public TimeSpan RefreshTokenLifetime { get; set; } = TimeSpan.FromDays(30);
    public TimeSpan AuthorizationCodeLifetime { get; set; } = TimeSpan.FromMinutes(10);
    public DateTime CreatedAt { get; set; }
    public DateTime UpdatedAt { get; set; }
    public string? CreatedBy { get; set; }
    public string? UpdatedBy { get; set; }
    public int ClientCount { get; set; }
}

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

/// <summary>
/// DTO for client data
/// </summary>
public class ClientDto
{
    public string Id { get; set; } = string.Empty;
    public string ClientId { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public string? Description { get; set; }
    public bool IsEnabled { get; set; }
    public ClientType ClientType { get; set; }
    public bool AllowAuthorizationCodeFlow { get; set; }
    public bool AllowClientCredentialsFlow { get; set; }
    public bool AllowPasswordFlow { get; set; }
    public bool AllowRefreshTokenFlow { get; set; }
    public bool RequirePkce { get; set; }
    public bool RequireClientSecret { get; set; }
    public TimeSpan? AccessTokenLifetime { get; set; }
    public TimeSpan? RefreshTokenLifetime { get; set; }
    public TimeSpan? AuthorizationCodeLifetime { get; set; }
    public string RealmId { get; set; } = string.Empty;
    public string RealmName { get; set; } = string.Empty;
    public DateTime CreatedAt { get; set; }
    public DateTime UpdatedAt { get; set; }
    public string? CreatedBy { get; set; }
    public string? UpdatedBy { get; set; }
    public List<string> RedirectUris { get; set; } = new();
    public List<string> PostLogoutUris { get; set; } = new();
    public List<string> Scopes { get; set; } = new();
    public List<string> Permissions { get; set; } = new();
}

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

/// <summary>
/// Request for updating clients
/// </summary>
public class UpdateClientRequest
{
    [StringLength(500)]
    public string? ClientSecret { get; set; }

    [StringLength(200)]
    public string? Name { get; set; }

    [StringLength(500)]
    public string? Description { get; set; }

    public bool? IsEnabled { get; set; }
    public ClientType? ClientType { get; set; }
    public bool? AllowAuthorizationCodeFlow { get; set; }
    public bool? AllowClientCredentialsFlow { get; set; }
    public bool? AllowPasswordFlow { get; set; }
    public bool? AllowRefreshTokenFlow { get; set; }
    public bool? RequirePkce { get; set; }
    public bool? RequireClientSecret { get; set; }

    public TimeSpan? AccessTokenLifetime { get; set; }
    public TimeSpan? RefreshTokenLifetime { get; set; }
    public TimeSpan? AuthorizationCodeLifetime { get; set; }

    public List<string>? RedirectUris { get; set; }
    public List<string>? PostLogoutUris { get; set; }
    public List<string>? Scopes { get; set; }
    public List<string>? Permissions { get; set; }
}