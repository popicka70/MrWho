namespace MrWho.Shared.Models;

public class ClientUserDto
{
    public string Id { get; set; } = string.Empty;
    public string ClientId { get; set; } = string.Empty; // DB client PK
    public string ClientPublicId { get; set; } = string.Empty; // Client.ClientId
    public string ClientName { get; set; } = string.Empty;
    public string UserId { get; set; } = string.Empty; // AspNetUsers PK
    public string UserName { get; set; } = string.Empty;
    public string? UserEmail { get; set; }
    public DateTime CreatedAt { get; set; }
}

public class AssignClientUserRequest
{
    public string UserId { get; set; } = string.Empty;
    public string ClientId { get; set; } = string.Empty; // DB client PK or public ClientId, server will accept both
}

public class ClientUsersListDto
{
    public string ClientId { get; set; } = string.Empty; // DB PK
    public string ClientPublicId { get; set; } = string.Empty;
    public string ClientName { get; set; } = string.Empty;
    public List<ClientUserDto> Users { get; set; } = new();
}
