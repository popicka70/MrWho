using System.Text;
using System.Text.Json;
using MrWho.Shared.Models;

namespace MrWhoAdmin.Web.Services;

public class ClientRolesApiService : IClientRolesApiService
{
    private readonly HttpClient _httpClient;
    private readonly ILogger<ClientRolesApiService> _logger;
    private readonly JsonSerializerOptions _jsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = true
    };

    public ClientRolesApiService(HttpClient httpClient, ILogger<ClientRolesApiService> logger)
    { _httpClient = httpClient; _logger = logger; }

    public async Task<List<ClientRoleDto>?> GetRolesAsync(string? clientId = null)
    {
        try
        {
            var url = string.IsNullOrWhiteSpace(clientId) ? "api/clientroles" : $"api/clientroles?clientId={Uri.EscapeDataString(clientId)}";
            var resp = await _httpClient.GetAsync(url);
            if (!resp.IsSuccessStatusCode)
            {
                return null;
            }

            var json = await resp.Content.ReadAsStringAsync();
            return JsonSerializer.Deserialize<List<ClientRoleDto>>(json, _jsonOptions);
        }
        catch (Exception ex) { _logger.LogError(ex, "GetRoles failed"); return null; }
    }

    public async Task<List<string>?> GetUserClientRolesAsync(string clientId, string userId)
    {
        try
        {
            var resp = await _httpClient.GetAsync($"api/clientroles/{Uri.EscapeDataString(clientId)}/users/{Uri.EscapeDataString(userId)}");
            if (!resp.IsSuccessStatusCode)
            {
                return null;
            }

            var json = await resp.Content.ReadAsStringAsync();
            return JsonSerializer.Deserialize<List<string>>(json, _jsonOptions);
        }
        catch (Exception ex) { _logger.LogError(ex, "GetUserClientRoles failed"); return null; }
    }

    public async Task<ClientRoleDto?> CreateRoleAsync(CreateClientRoleRequest request)
    {
        try
        {
            var json = JsonSerializer.Serialize(request, _jsonOptions);
            var resp = await _httpClient.PostAsync("api/clientroles", new StringContent(json, Encoding.UTF8, "application/json"));
            if (!resp.IsSuccessStatusCode)
            {
                return null;
            }

            var body = await resp.Content.ReadAsStringAsync();
            return JsonSerializer.Deserialize<ClientRoleDto>(body, _jsonOptions);
        }
        catch (Exception ex) { _logger.LogError(ex, "CreateRole failed"); return null; }
    }

    public async Task<bool> DeleteRoleAsync(DeleteClientRoleRequest request)
    {
        try
        {
            var json = JsonSerializer.Serialize(request, _jsonOptions);
            var msg = new HttpRequestMessage(HttpMethod.Delete, "api/clientroles") { Content = new StringContent(json, Encoding.UTF8, "application/json") };
            var resp = await _httpClient.SendAsync(msg);
            return resp.IsSuccessStatusCode;
        }
        catch (Exception ex) { _logger.LogError(ex, "DeleteRole failed"); return false; }
    }

    public async Task<bool> AssignRoleAsync(AssignClientRoleRequest request)
    {
        try
        {
            var json = JsonSerializer.Serialize(request, _jsonOptions);
            var resp = await _httpClient.PostAsync("api/clientroles/assign", new StringContent(json, Encoding.UTF8, "application/json"));
            return resp.IsSuccessStatusCode;
        }
        catch (Exception ex) { _logger.LogError(ex, "AssignRole failed"); return false; }
    }

    public async Task<bool> RemoveRoleAsync(RemoveClientRoleRequest request)
    {
        try
        {
            var json = JsonSerializer.Serialize(request, _jsonOptions);
            var resp = await _httpClient.PostAsync("api/clientroles/remove", new StringContent(json, Encoding.UTF8, "application/json"));
            return resp.IsSuccessStatusCode;
        }
        catch (Exception ex) { _logger.LogError(ex, "RemoveRole failed"); return false; }
    }
}
