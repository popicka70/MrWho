using System.Text.Json;

namespace MrWhoAdmin.Web.Services;

public class ClientRoleUsersApiService : IClientRoleUsersApiService
{
    private readonly HttpClient _httpClient;
    private readonly ILogger<ClientRoleUsersApiService> _logger;
    private readonly JsonSerializerOptions _json = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase, PropertyNameCaseInsensitive = true };
    public ClientRoleUsersApiService(HttpClient httpClient, ILogger<ClientRoleUsersApiService> logger) { _httpClient = httpClient; _logger = logger; }

    public async Task<List<ClientRoleUserDto>> GetUsersForRoleAsync(string clientId, string roleName)
    {
        try
        {
            var resp = await _httpClient.GetAsync($"api/clientroles/{Uri.EscapeDataString(clientId)}/roles/{Uri.EscapeDataString(roleName)}/users");
            if (!resp.IsSuccessStatusCode)
            {
                return new();
            }

            var json = await resp.Content.ReadAsStringAsync();
            return JsonSerializer.Deserialize<List<ClientRoleUserDto>>(json, _json) ?? new();
        }
        catch (Exception ex) { _logger.LogError(ex, "GetUsersForRole failed"); return new(); }
    }
}
