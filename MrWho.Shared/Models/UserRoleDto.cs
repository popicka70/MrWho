namespace MrWho.Shared.Models;

/// <summary>
/// User role assignment DTO
/// </summary>
public class UserRoleDto
{
    public string UserId { get; set; } = string.Empty;
    public string UserName { get; set; } = string.Empty;
    public string Email { get; set; } = string.Empty;
    public string RoleId { get; set; } = string.Empty;
    public string RoleName { get; set; } = string.Empty;
    public DateTime AssignedAt { get; set; }
    public string? AssignedBy { get; set; }
}
