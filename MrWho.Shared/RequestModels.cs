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

/// <summary>
/// Request to create a new client
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

/// <summary>
/// Request to create a new role
/// </summary>
public class CreateRoleRequest
{
    [Required]
    [StringLength(256)]
    public string Name { get; set; } = string.Empty;
    
    [StringLength(500)]
    public string? Description { get; set; }
    
    public bool IsEnabled { get; set; } = true;
}

/// <summary>
/// Request to update a role
/// </summary>
public class UpdateRoleRequest
{
    [StringLength(256)]
    public string? Name { get; set; }
    
    [StringLength(500)]
    public string? Description { get; set; }
    
    public bool? IsEnabled { get; set; }
}

/// <summary>
/// Request to assign role to user
/// </summary>
public class AssignRoleRequest
{
    [Required]
    public string UserId { get; set; } = string.Empty;
    
    [Required]
    public string RoleId { get; set; } = string.Empty;
}

/// <summary>
/// Request to remove role from user
/// </summary>
public class RemoveRoleRequest
{
    [Required]
    public string UserId { get; set; } = string.Empty;
    
    [Required]
    public string RoleId { get; set; } = string.Empty;
}

/// <summary>
/// Request to create a new user
/// </summary>
public class CreateUserRequest
{
    [Required]
    [StringLength(256)]
    public string UserName { get; set; } = string.Empty;

    [Required]
    [EmailAddress]
    [StringLength(256)]
    public string Email { get; set; } = string.Empty;

    [Required]
    [StringLength(100, MinimumLength = 6)]
    public string Password { get; set; } = string.Empty;

    [Phone]
    public string? PhoneNumber { get; set; }

    public bool EmailConfirmed { get; set; } = false;
    public bool PhoneNumberConfirmed { get; set; } = false;
    public bool TwoFactorEnabled { get; set; } = false;
}

/// <summary>
/// Request to update a user
/// </summary>
public class UpdateUserRequest
{
    [StringLength(256)]
    public string? UserName { get; set; }

    [EmailAddress]
    [StringLength(256)]
    public string? Email { get; set; }

    [Phone]
    public string? PhoneNumber { get; set; }

    public bool? EmailConfirmed { get; set; }
    public bool? PhoneNumberConfirmed { get; set; }
    public bool? TwoFactorEnabled { get; set; }
}