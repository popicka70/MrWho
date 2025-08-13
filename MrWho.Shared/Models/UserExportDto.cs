namespace MrWho.Shared.Models;

/// <summary>
/// JSON-exportable representation of a user. Excludes password hash/ids.
/// </summary>
public class UserExportDto
{
    public string UserName { get; set; } = string.Empty;
    public string Email { get; set; } = string.Empty;
    public bool EmailConfirmed { get; set; }
    public string? PhoneNumber { get; set; }
    public bool PhoneNumberConfirmed { get; set; }
    public bool TwoFactorEnabled { get; set; }
    public bool LockoutEnabled { get; set; }
    public DateTimeOffset? LockoutEnd { get; set; }

    // Claims and roles
    public List<UserClaimDto> Claims { get; set; } = new();
    public List<string> Roles { get; set; } = new();

    // Optional: temp password to set on import (set only if creating a new user)
    public string? TempPassword { get; set; }
}
