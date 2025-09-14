namespace MrWho.Shared.Models;

/// <summary>
/// DTO for Identity Resource Claims - represents the IdentityResourceClaim entity
/// </summary>
public class IdentityResourceClaimDto
{
    /// <summary>
    /// Unique identifier for the claim
    /// </summary>
    public string Id { get; set; } = string.Empty;

    /// <summary>
    /// The identity resource this claim belongs to
    /// </summary>
    public string IdentityResourceId { get; set; } = string.Empty;

    /// <summary>
    /// The claim type (e.g., "given_name", "email", "role")
    /// </summary>
    public string ClaimType { get; set; } = string.Empty;

    /// <summary>
    /// Display name for the claim type (for UI purposes) - computed from ClaimType
    /// </summary>
    public string? DisplayName { get; set; }

    /// <summary>
    /// Description of what this claim type represents - computed from ClaimType
    /// </summary>
    public string? Description { get; set; }

    /// <summary>
    /// Whether this is a standard OIDC claim or a custom claim - computed from ClaimType
    /// </summary>
    public bool IsStandard { get; set; }

    /// <summary>
    /// Creates an IdentityResourceClaimDto from just a claim type string (for backward compatibility)
    /// </summary>
    public static IdentityResourceClaimDto FromClaimType(string claimType, string? identityResourceId = null)
    {
        var standardClaim = CommonClaimTypes.StandardClaims.FirstOrDefault(s => s.Type == claimType);
        var displayName = standardClaim?.DisplayName ??
            System.Globalization.CultureInfo.CurrentCulture.TextInfo.ToTitleCase(claimType.Replace("_", " ").ToLower());

        return new IdentityResourceClaimDto
        {
            Id = string.Empty, // Will be populated when saved to database
            IdentityResourceId = identityResourceId ?? string.Empty,
            ClaimType = claimType,
            DisplayName = displayName,
            Description = standardClaim?.Description ?? "Custom claim type",
            IsStandard = standardClaim != null
        };
    }

    /// <summary>
    /// Creates an IdentityResourceClaimDto from a ClaimTypeInfo
    /// </summary>
    public static IdentityResourceClaimDto FromClaimTypeInfo(ClaimTypeInfo claimTypeInfo, string? identityResourceId = null)
    {
        return new IdentityResourceClaimDto
        {
            Id = string.Empty, // Will be populated when saved to database
            IdentityResourceId = identityResourceId ?? string.Empty,
            ClaimType = claimTypeInfo.Type,
            DisplayName = claimTypeInfo.DisplayName,
            Description = claimTypeInfo.Description,
            IsStandard = CommonClaimTypes.StandardClaims.Any(s => s.Type == claimTypeInfo.Type)
        };
    }
}
