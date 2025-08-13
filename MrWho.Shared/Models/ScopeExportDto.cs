namespace MrWho.Shared.Models;

/// <summary>
/// JSON-exportable representation of a scope. Portable (no database IDs).
/// </summary>
public class ScopeExportDto
{
    public string Name { get; set; } = string.Empty;
    public string? DisplayName { get; set; }
    public string? Description { get; set; }
    public bool IsEnabled { get; set; } = true;
    public bool IsRequired { get; set; } = false;
    public bool ShowInDiscoveryDocument { get; set; } = true;
    public ScopeType Type { get; set; } = ScopeType.Identity;

    // Claims included in this scope
    public List<string> Claims { get; set; } = new();
}
