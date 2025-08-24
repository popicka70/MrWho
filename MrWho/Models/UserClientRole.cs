namespace MrWho.Models;

public class UserClientRole
{
    public string UserId { get; set; } = string.Empty; // FK to AspNetUsers
    public Guid ClientRoleId { get; set; }

    public ClientRole ClientRole { get; set; } = null!;
}
