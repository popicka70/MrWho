namespace MrWho.Models;

/// <summary>
/// API Resource entity - represents an API that can be protected
/// </summary>
public class ApiResource
{
    public string Id { get; set; } = Guid.NewGuid().ToString();
    public string Name { get; set; } = string.Empty;
    public string? DisplayName { get; set; }
    public string? Description { get; set; }
    public bool IsEnabled { get; set; } = true;
    public bool IsStandard { get; set; } = false;
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime? UpdatedAt { get; set; }
    public string? CreatedBy { get; set; }
    public string? UpdatedBy { get; set; }

    /// <summary>
    /// JSON array (e.g. ["access_token","identity_token"]) of OpenIddict destinations to apply to claims from this API resource.
    /// If null or empty, defaults to ["access_token"].
    /// </summary>
    public string? ClaimDestinationsJson { get; set; }

    // Navigation properties
    public virtual ICollection<ApiResourceScope> Scopes { get; set; } = new List<ApiResourceScope>();
    public virtual ICollection<ApiResourceClaim> UserClaims { get; set; } = new List<ApiResourceClaim>();
    public virtual ICollection<ApiResourceSecret> Secrets { get; set; } = new List<ApiResourceSecret>();
}

/// <summary>
/// API Resource Scope - represents scopes that belong to an API resource
/// </summary>
public class ApiResourceScope
{
    public string Id { get; set; } = Guid.NewGuid().ToString();
    public string ApiResourceId { get; set; } = string.Empty;
    public string Scope { get; set; } = string.Empty;

    // Navigation properties
    public virtual ApiResource ApiResource { get; set; } = default!;
}

/// <summary>
/// API Resource Claim - represents user claims that should be included when accessing this API
/// </summary>
public class ApiResourceClaim
{
    public string Id { get; set; } = Guid.NewGuid().ToString();
    public string ApiResourceId { get; set; } = string.Empty;
    public string ClaimType { get; set; } = string.Empty;

    // Navigation properties
    public virtual ApiResource ApiResource { get; set; } = default!;
}

/// <summary>
/// API Resource Secret - represents secrets for this API resource (for introspection, etc.)
/// </summary>
public class ApiResourceSecret
{
    public string Id { get; set; } = Guid.NewGuid().ToString();
    public string ApiResourceId { get; set; } = string.Empty;
    public string? Description { get; set; }
    public string Value { get; set; } = string.Empty;
    public DateTime? Expiration { get; set; }
    public string Type { get; set; } = "SharedSecret";
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    // Navigation properties
    public virtual ApiResource ApiResource { get; set; } = default!;
}
