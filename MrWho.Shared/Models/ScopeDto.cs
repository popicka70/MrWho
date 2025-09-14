using MrWho.Shared.Models;

namespace MrWho.Shared.Models;

/// <summary>
/// Scope DTO for API responses
/// </summary>
public class ScopeDto
{
    public string Id { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public string? DisplayName { get; set; }
    public string? Description { get; set; }
    public bool IsEnabled { get; set; } = true;
    public bool IsRequired { get; set; } = false;
    public bool ShowInDiscoveryDocument { get; set; } = true;
    public bool IsStandard { get; set; } = false;
    public ScopeType Type { get; set; } = ScopeType.Identity;
    public DateTime CreatedAt { get; set; }
    public DateTime? UpdatedAt { get; set; }
    public string? CreatedBy { get; set; }
    public string? UpdatedBy { get; set; }
    public List<string> Claims { get; set; } = new();
}

/// <summary>
/// Request model for creating a new scope
/// </summary>
public class CreateScopeRequest
{
    public string Name { get; set; } = string.Empty;
    public string? DisplayName { get; set; }
    public string? Description { get; set; }
    public bool IsEnabled { get; set; } = true;
    public bool IsRequired { get; set; } = false;
    public bool ShowInDiscoveryDocument { get; set; } = true;
    public ScopeType Type { get; set; } = ScopeType.Identity;
    public List<string> Claims { get; set; } = new();
}

/// <summary>
/// Request model for updating an existing scope
/// </summary>
public class UpdateScopeRequest
{
    public string? DisplayName { get; set; }
    public string? Description { get; set; }
    public bool? IsEnabled { get; set; }
    public bool? IsRequired { get; set; }
    public bool? ShowInDiscoveryDocument { get; set; }
    public ScopeType? Type { get; set; }
    public List<string>? Claims { get; set; }
}

/// <summary>
/// Type of scope
/// </summary>
public enum ScopeType
{
    Identity = 0,
    Resource = 1
}
