using System.ComponentModel.DataAnnotations;

namespace MrWho.Models;

public class WebAuthnCredential
{
    public Guid Id { get; set; } = Guid.NewGuid();

    [Required]
    public string UserId { get; set; } = string.Empty;

    // base64url-encoded credential ID
    [Required]
    public string CredentialId { get; set; } = string.Empty;

    // COSE public key (base64url)
    [Required]
    public string PublicKey { get; set; } = string.Empty;

    // base64url user handle (typically user Id encoded)
    [Required]
    public string UserHandle { get; set; } = string.Empty;

    public uint SignCount { get; set; }

    public string? AaGuid { get; set; }

    public string? AttestationFmt { get; set; }

    public bool IsDiscoverable { get; set; }

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    public string? Nickname { get; set; }
}
