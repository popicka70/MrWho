namespace MrWho.Shared.Models;

/// <summary>
/// User claim DTO
/// </summary>
public class UserClaimDto
{
    public string ClaimType { get; set; } = string.Empty;
    public string ClaimValue { get; set; } = string.Empty;
    public string? Issuer { get; set; }
}
