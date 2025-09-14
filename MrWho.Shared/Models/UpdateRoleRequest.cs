using System.ComponentModel.DataAnnotations;

namespace MrWho.Shared.Models;

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
