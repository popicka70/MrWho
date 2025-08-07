namespace MrWho.Shared.Models;

/// <summary>
/// DTO for Identity Resource Claims - represents claim types that can be included in an identity resource
/// </summary>
public class IdentityResourceClaimDto
{
    /// <summary>
    /// The claim type (e.g., "given_name", "email", "role")
    /// </summary>
    public string ClaimType { get; set; } = string.Empty;

    /// <summary>
    /// Display name for the claim type (for UI purposes)
    /// </summary>
    public string? DisplayName { get; set; }

    /// <summary>
    /// Description of what this claim type represents
    /// </summary>
    public string? Description { get; set; }

    /// <summary>
    /// Whether this is a standard OIDC claim or a custom claim
    /// </summary>
    public bool IsStandard { get; set; }

    /// <summary>
    /// Creates an IdentityResourceClaimDto from a ClaimTypeInfo
    /// </summary>
    public static IdentityResourceClaimDto FromClaimTypeInfo(ClaimTypeInfo claimTypeInfo)
    {
        return new IdentityResourceClaimDto
        {
            ClaimType = claimTypeInfo.Type,
            DisplayName = claimTypeInfo.DisplayName,
            Description = claimTypeInfo.Description,
            IsStandard = CommonClaimTypes.StandardClaims.Any(s => s.Type == claimTypeInfo.Type)
        };
    }

    /// <summary>
    /// Creates an IdentityResourceClaimDto from just a claim type string
    /// </summary>
    public static IdentityResourceClaimDto FromClaimType(string claimType)
    {
        var standardClaim = CommonClaimTypes.StandardClaims.FirstOrDefault(s => s.Type == claimType);
        
        return new IdentityResourceClaimDto
        {
            ClaimType = claimType,
            DisplayName = standardClaim?.DisplayName ?? claimType.Replace("_", " ").ToTitleCase(),
            Description = standardClaim?.Description ?? "Custom claim type",
            IsStandard = standardClaim != null
        };
    }
}

/// <summary>
/// Extension methods for string manipulation
/// </summary>
public static class IdentityResourceStringExtensions
{
    public static string ToTitleCase(this string input)
    {
        if (string.IsNullOrEmpty(input))
            return input;

        return System.Globalization.CultureInfo.CurrentCulture.TextInfo.ToTitleCase(input.ToLower());
    }
}