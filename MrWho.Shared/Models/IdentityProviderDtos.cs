using MrWho.Shared;

namespace MrWho.Shared.Models;

public class IdentityProviderDto
{
    public string Id { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public string? DisplayName { get; set; }
    public IdentityProviderType Type { get; set; }
    public bool IsEnabled { get; set; }
    public string? RealmId { get; set; }
    public string? IconUri { get; set; }
    public int Order { get; set; }

    // OIDC
    public string? Authority { get; set; }
    public string? MetadataAddress { get; set; }
    public string? ClientId { get; set; }
    public string? ClientSecret { get; set; }
    public string? Scopes { get; set; }
    public string? ResponseType { get; set; }
    public bool? UsePkce { get; set; }
    public bool? GetClaimsFromUserInfoEndpoint { get; set; }
    public string? ClaimMappingsJson { get; set; }

    // SAML2
    public string? SamlEntityId { get; set; }
    public string? SamlSingleSignOnUrl { get; set; }
    public string? SamlCertificate { get; set; }
    public bool? SamlWantAssertionsSigned { get; set; }
    public bool? SamlValidateIssuer { get; set; }
}

public class ClientIdentityProviderDto
{
    public string Id { get; set; } = string.Empty;
    public string ClientId { get; set; } = string.Empty; // DB id
    public string IdentityProviderId { get; set; } = string.Empty;
    public string? DisplayNameOverride { get; set; }
    public bool? IsEnabled { get; set; }
    public int? Order { get; set; }
    public string? OptionsJson { get; set; }
}
