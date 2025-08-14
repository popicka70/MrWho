namespace MrWho.Shared.Models;

public class UserClientDto
{
    public string ClientId { get; set; } = string.Empty; // DB PK
    public string ClientPublicId { get; set; } = string.Empty; // Client.ClientId
    public string ClientName { get; set; } = string.Empty;
    public DateTime CreatedAt { get; set; }
}

public class UserClientsListDto
{
    public string UserId { get; set; } = string.Empty;
    public string UserName { get; set; } = string.Empty;
    public string? UserEmail { get; set; }
    public List<UserClientDto> Clients { get; set; } = new();
}
