using System.ComponentModel.DataAnnotations;
using MrWho.Shared;

namespace MrWho.Shared.Models;

/// <summary>
/// Request to update a client
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