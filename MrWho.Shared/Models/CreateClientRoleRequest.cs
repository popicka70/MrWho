using System.ComponentModel.DataAnnotations;

namespace MrWho.Shared.Models;

public class CreateClientRoleRequest
{
    [Required] public string ClientId { get; set; } = string.Empty; // public client id
    [Required] [StringLength(256)] public string Name { get; set; } = string.Empty;
}
