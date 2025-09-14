using System.ComponentModel.DataAnnotations;

namespace MrWho.Shared.Models;

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
