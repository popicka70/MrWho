using System.ComponentModel.DataAnnotations;

namespace MrWho.Models;

public enum KeyMaterialStatus
{
    Created = 0,
    Active = 1,
    Retiring = 2,
    Retired = 3,
    Revoked = 4
}

/// <summary>
/// Persistent signing/encryption key material with rotation metadata.
/// Private key is stored as PKCS#8 PEM (unprotected). In production, protect at-rest via KMS/HSM.
/// </summary>
public class KeyMaterial
{
    [Key]
    public string Id { get; set; } = Guid.NewGuid().ToString();

    /// <summary>
    /// Key use: "sig" for signing, "enc" for encryption.
    /// </summary>
    [Required]
    [StringLength(10)]
    public string Use { get; set; } = "sig";

    /// <summary>
    /// Key identifier (kid) advertised in JWKS and attached to tokens.
    /// </summary>
    [Required]
    [StringLength(200)]
    public string Kid { get; set; } = Guid.NewGuid().ToString("n");

    /// <summary>
    /// JWA algorithm identifier (e.g., RS256, RSA-OAEP-256).
    /// </summary>
    [Required]
    [StringLength(50)]
    public string Algorithm { get; set; } = "RS256";

    /// <summary>
    /// Key type (RSA, EC). Only RSA is supported for now.
    /// </summary>
    [Required]
    [StringLength(20)]
    public string KeyType { get; set; } = "RSA";

    /// <summary>
    /// Key size in bits (e.g., 2048, 3072, 4096).
    /// </summary>
    public int KeySize { get; set; } = 2048;

    /// <summary>
    /// Private key in PKCS#8 PEM format (BEGIN PRIVATE KEY/END PRIVATE KEY).
    /// </summary>
    [Required]
    public string PrivateKeyPem { get; set; } = string.Empty;

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime ActivateAt { get; set; } = DateTime.UtcNow;
    public DateTime? RetireAt { get; set; }
    public DateTime? RevokedAt { get; set; }

    public bool IsPrimary { get; set; } = false;

    public KeyMaterialStatus Status { get; set; } = KeyMaterialStatus.Created;
}
