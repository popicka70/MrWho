namespace MrWho.Shared.Models;

public class ClientImportResult
{
    public ClientDto Client { get; set; } = new();
    public string? GeneratedClientSecret { get; set; }
}
