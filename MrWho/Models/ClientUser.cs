using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using Microsoft.AspNetCore.Identity;

namespace MrWho.Models;

/// <summary>
/// Join entity mapping a user to a client they are allowed to access
/// </summary>
public class ClientUser
{
    [Key]
    public string Id { get; set; } = Guid.NewGuid().ToString();

    [Required]
    public string ClientId { get; set; } = string.Empty; // FK -> Client.Id

    [Required]
    public string UserId { get; set; } = string.Empty; // FK -> AspNetUsers.Id

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public string? CreatedBy { get; set; }

    [ForeignKey(nameof(ClientId))]
    public virtual Client Client { get; set; } = null!;

    [ForeignKey(nameof(UserId))]
    public virtual IdentityUser User { get; set; } = null!;
}
