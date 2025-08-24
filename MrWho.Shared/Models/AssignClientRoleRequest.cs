using System.ComponentModel.DataAnnotations;

namespace MrWho.Shared.Models;

public class AssignClientRoleRequest
{
    [Required] public string UserId { get; set; } = string.Empty;
    [Required] public string ClientId { get; set; } = string.Empty; // public client id
    [Required] public string RoleName { get; set; } = string.Empty;
}
