using MrWho.Shared.Models;

namespace MrWho.Shared.Models;

/// <summary>
/// API Resource DTO for API responses
/// </summary>
public class ApiResourceDto
{
    public string Id { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public string? DisplayName { get; set; }
    public string? Description { get; set; }
    public bool IsEnabled { get; set; } = true;
    public bool IsStandard { get; set; } = false;
    public DateTime CreatedAt { get; set; }
    public DateTime? UpdatedAt { get; set; }
    public string? CreatedBy { get; set; }
    public string? UpdatedBy { get; set; }
    public List<string> Scopes { get; set; } = new();
    public List<string> UserClaims { get; set; } = new();
    public List<ApiSecretDto> Secrets { get; set; } = new();
}

/// <summary>
/// API Secret DTO for API Resource secrets
/// </summary>
public class ApiSecretDto
{
    public string Id { get; set; } = string.Empty;
    public string? Description { get; set; }
    public string Value { get; set; } = string.Empty;
    public DateTime? Expiration { get; set; }
    public string Type { get; set; } = "SharedSecret";
    public DateTime CreatedAt { get; set; }
}

/// <summary>
/// Request model for creating a new API resource
/// </summary>
public class CreateApiResourceRequest
{
    public string Name { get; set; } = string.Empty;
    public string? DisplayName { get; set; }
    public string? Description { get; set; }
    public bool IsEnabled { get; set; } = true;
    public List<string> Scopes { get; set; } = new();
    public List<string> UserClaims { get; set; } = new();
    public List<CreateApiSecretRequest> Secrets { get; set; } = new();
}

/// <summary>
/// Request model for updating an existing API resource
/// </summary>
public class UpdateApiResourceRequest
{
    public string? DisplayName { get; set; }
    public string? Description { get; set; }
    public bool? IsEnabled { get; set; }
    public List<string>? Scopes { get; set; }
    public List<string>? UserClaims { get; set; }
    public List<CreateApiSecretRequest>? Secrets { get; set; }
}

/// <summary>
/// Request model for creating API resource secrets
/// </summary>
public class CreateApiSecretRequest
{
    public string? Description { get; set; }
    public string Value { get; set; } = string.Empty;
    public DateTime? Expiration { get; set; }
    public string Type { get; set; } = "SharedSecret";
}