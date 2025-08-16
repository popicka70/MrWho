namespace MrWho.Shared.Models;

public class AuditLogDto
{
    public string Id { get; set; } = string.Empty;
    public DateTime OccurredAt { get; set; }
    public string? UserId { get; set; }
    public string? UserName { get; set; }
    public string? IpAddress { get; set; }
    public string EntityType { get; set; } = string.Empty;
    public string EntityId { get; set; } = string.Empty;
    public string Action { get; set; } = string.Empty;
    public string? Changes { get; set; }
    public string? RealmId { get; set; }
    public string? ClientId { get; set; }
}
