using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace MrWho.Models;

/// <summary>
/// Client allowed scopes
/// </summary>
public class ClientScope
{
    [Key]
    public string Id { get; set; } = Guid.NewGuid().ToString();

    [Required]
    [StringLength(200)]
    public string Scope { get; set; } = string.Empty;

    [Required]
    public string ClientId { get; set; } = string.Empty;

    [ForeignKey(nameof(ClientId))]
    public virtual Client Client { get; set; } = null!;
}
