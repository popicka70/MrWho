using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace MrWho.Models;

public class ClientAudience
{
    [Key]
    public string Id { get; set; } = Guid.NewGuid().ToString();

    [Required]
    public string ClientId { get; set; } = string.Empty;

    [ForeignKey(nameof(ClientId))]
    public Client Client { get; set; } = null!;

    [Required]
    [StringLength(200)]
    public string Audience { get; set; } = string.Empty;

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public string? CreatedBy { get; set; }
}
