using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace MrWho.Models;

public class ClientSecretHistory
{
    [Key]
    public string Id { get; set; } = Guid.NewGuid().ToString();

    [Required]
    public string ClientId { get; set; } = string.Empty; // FK to Client.Id

    [ForeignKey(nameof(ClientId))]
    public Client Client { get; set; } = null!;

    [Required]
    [StringLength(2000)]
    public string SecretHash { get; set; } = string.Empty; // format: algo$params$hash

    [Required]
    [StringLength(50)]
    public string Algo { get; set; } = "PBKDF2-SHA256"; // or ARGON2ID

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime? LastUsedAt { get; set; }
    public DateTime? ExpiresAt { get; set; }

    public ClientSecretStatus Status { get; set; } = ClientSecretStatus.Active;

    public bool IsCompromised { get; set; }

    /// <summary>
    /// Encrypted (reversible) copy of the plaintext secret for HMAC (HS*) JAR validation.
    /// Null for legacy records created before introduction of reversible storage.
    /// Protected with ASP.NET Data Protection (purpose: MrWho.ClientSecret.V1).
    /// </summary>
    [StringLength(4000)]
    public string? EncryptedSecret { get; set; }
}
