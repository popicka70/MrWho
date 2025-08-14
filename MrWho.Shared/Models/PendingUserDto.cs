using System.ComponentModel.DataAnnotations;

namespace MrWho.Shared.Models;

public class PendingUserDto
{
    public string Id { get; set; } = string.Empty;
    public string UserName { get; set; } = string.Empty;
    public string Email { get; set; } = string.Empty;
    public string? FirstName { get; set; }
    public string? LastName { get; set; }
    public string? DisplayName { get; set; }
    public string State { get; set; } = "New";
    public DateTime CreatedAt { get; set; }
}
