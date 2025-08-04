using MrWho.Shared;

namespace MrWho.Shared.Models;

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