using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace MrWho.Models;

public class ClientRole
{
    [Key]
    public Guid Id { get; set; } = Guid.NewGuid();

    [Required]
    [StringLength(256)]
    public string Name { get; set; } = string.Empty;

    [Required]
    [StringLength(256)]
    public string NormalizedName { get; set; } = string.Empty;

    [Required]
    public string ClientId { get; set; } = string.Empty;

    [ForeignKey(nameof(ClientId))]
    public Client Client { get; set; } = null!;

    [StringLength(40)]
    public string? ConcurrencyStamp { get; set; } = Guid.NewGuid().ToString("N");

    public ICollection<UserClientRole> UserClientRoles { get; set; } = new List<UserClientRole>();
}
