namespace MrWho.Shared.Models;

public class ClientRoleDto
{
    public Guid Id { get; set; }
    public string Name { get; set; } = string.Empty;
    public string ClientId { get; set; } = string.Empty; // public client identifier
    public int UserCount { get; set; }
}
