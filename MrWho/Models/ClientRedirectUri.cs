using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace MrWho.Models;

/// <summary>
/// Client redirect URIs
/// </summary>
public class ClientRedirectUri
{
    [Key]
    public string Id { get; set; } = Guid.NewGuid().ToString();

    [Required]
    [StringLength(2000)]
    public string Uri { get; set; } = string.Empty;

    [Required]
    public string ClientId { get; set; } = string.Empty;

    [ForeignKey(nameof(ClientId))]
    public virtual Client Client { get; set; } = null!;
}
