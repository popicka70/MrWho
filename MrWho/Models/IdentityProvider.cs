using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using MrWho.Shared;

namespace MrWho.Models;

/// <summary>
/// External Identity Provider (IdP) that this server can broker to.
/// Supports OpenID Connect and SAML2 (SAML fields optional).
/// </summary>
public class IdentityProvider
{
    [Key]
    public string Id { get; set; } = Guid.NewGuid().ToString();

    [Required, StringLength(200)]
    public string Name { get; set; } = string.Empty; // unique within realm

    [StringLength(200)]
    public string? DisplayName { get; set; }

    [Required]
    public IdentityProviderType Type { get; set; } = IdentityProviderType.Oidc;

    [Required]
    public bool IsEnabled { get; set; } = true;

    // Realm scoping (optional): null means global
    public string? RealmId { get; set; }

    [ForeignKey(nameof(RealmId))]
    public virtual Realm? Realm { get; set; }

    // Common
    [StringLength(2000)]
    public string? IconUri { get; set; }
    public int Order { get; set; } = 0;

    // OIDC configuration
    [StringLength(2000)]
    public string? Authority { get; set; }

    [StringLength(2000)]
    public string? MetadataAddress { get; set; }

    [StringLength(200)]
    public string? ClientId { get; set; }

    [StringLength(500)]
    public string? ClientSecret { get; set; }

    [StringLength(1000)]
    public string? Scopes { get; set; } // space-separated or JSON array

    [StringLength(50)]
    public string? ResponseType { get; set; } // default: code

    public bool? UsePkce { get; set; }

    public bool? GetClaimsFromUserInfoEndpoint { get; set; }

    // Optional claim mapping JSON (external -> local)
    [StringLength(4000)]
    public string? ClaimMappingsJson { get; set; }

    // SAML2 configuration (optional)
    [StringLength(2000)]
    public string? SamlEntityId { get; set; }

    [StringLength(2000)]
    public string? SamlSingleSignOnUrl { get; set; }

    [StringLength(4000)]
    public string? SamlCertificate { get; set; } // PEM or thumbprint reference

    public bool? SamlWantAssertionsSigned { get; set; }

    public bool? SamlValidateIssuer { get; set; }

    // Audit
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;
    public string? CreatedBy { get; set; }
    public string? UpdatedBy { get; set; }

    // Navigation
    public virtual ICollection<ClientIdentityProvider> ClientLinks { get; set; } = new List<ClientIdentityProvider>();
}

/// <summary>
/// Per-client assignment for an external IdP with optional overrides.
/// </summary>
public class ClientIdentityProvider
{
    [Key]
    public string Id { get; set; } = Guid.NewGuid().ToString();

    [Required]
    public string ClientId { get; set; } = string.Empty; // FK to Client

    [ForeignKey(nameof(ClientId))]
    public virtual Client Client { get; set; } = null!;

    [Required]
    public string IdentityProviderId { get; set; } = string.Empty; // FK to IdentityProvider

    [ForeignKey(nameof(IdentityProviderId))]
    public virtual IdentityProvider IdentityProvider { get; set; } = null!;

    // Overrides
    [StringLength(200)]
    public string? DisplayNameOverride { get; set; }

    public bool? IsEnabled { get; set; }

    public int? Order { get; set; }

    // JSON blob for future per-client options (scopes, claim mappings, etc.)
    [StringLength(4000)]
    public string? OptionsJson { get; set; }

    // Audit
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;
    public string? CreatedBy { get; set; }
    public string? UpdatedBy { get; set; }
}
