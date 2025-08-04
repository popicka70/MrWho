using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace MrWho.Models;

/// <summary>
/// Claims included in a scope
/// </summary>
public class ScopeClaim
{
    [Key]
    public string Id { get; set; } = Guid.NewGuid().ToString();

    [Required]
    [StringLength(100)]
    public string ClaimType { get; set; } = string.Empty;

    [Required]
    public string ScopeId { get; set; } = string.Empty;

    [ForeignKey(nameof(ScopeId))]
    public virtual Scope Scope { get; set; } = null!;
}