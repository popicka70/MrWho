using System.ComponentModel.DataAnnotations;

namespace MrWho.Shared.Models;

public class DeleteClientRoleRequest
{
    [Required] public string ClientId { get; set; } = string.Empty; // public client id
    [Required] public string Name { get; set; } = string.Empty;
}
