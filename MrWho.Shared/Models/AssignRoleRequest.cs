using System.ComponentModel.DataAnnotations;

namespace MrWho.Shared.Models;

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