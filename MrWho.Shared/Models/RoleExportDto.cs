namespace MrWho.Shared.Models;

/// <summary>
/// JSON-exportable representation of an ASP.NET Identity role.
/// </summary>
public class RoleExportDto
{
    public string Name { get; set; } = string.Empty;
    public List<RoleClaimDto> Claims { get; set; } = new();
}
