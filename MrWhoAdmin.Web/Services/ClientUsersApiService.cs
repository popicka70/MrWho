using System.Text;
using System.Text.Json;
using MrWho.Shared.Models;

namespace MrWhoAdmin.Web.Services;

public class ClientUsersApiService : IClientUsersApiService
{
    private readonly HttpClient _httpClient;
    private readonly ILogger<ClientUsersApiService> _logger;
    private readonly JsonSerializerOptions _jsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = true
    };

    public ClientUsersApiService(HttpClient httpClient, ILogger<ClientUsersApiService> logger)
    {
        _httpClient = httpClient;
        _logger = logger;
    }

    public async Task<ClientUsersListDto?> GetClientUsersAsync(string clientIdOrPublicId)
    {
        try
        {
            var response = await _httpClient.GetAsync($"api/clients/{Uri.EscapeDataString(clientIdOrPublicId)}/users");
            response.EnsureSuccessStatusCode();
            var json = await response.Content.ReadAsStringAsync();
            return JsonSerializer.Deserialize<ClientUsersListDto>(json, _jsonOptions);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting users for client {Client}", clientIdOrPublicId);
            return null;
        }
    }

    public async Task<ClientUserDto?> AssignUserAsync(string clientIdOrPublicId, AssignClientUserRequest request)
    {
        try
        {
            var json = JsonSerializer.Serialize(request, _jsonOptions);
            var content = new StringContent(json, Encoding.UTF8, "application/json");
            var response = await _httpClient.PostAsync($"api/clients/{Uri.EscapeDataString(clientIdOrPublicId)}/users", content);
            response.EnsureSuccessStatusCode();
            var responseJson = await response.Content.ReadAsStringAsync();
            return JsonSerializer.Deserialize<ClientUserDto>(responseJson, _jsonOptions);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error assigning user {User} to client {Client}", request.UserId, clientIdOrPublicId);
            return null;
        }
    }

    public async Task<bool> RemoveUserAsync(string clientIdOrPublicId, string userId)
    {
        try
        {
            var response = await _httpClient.DeleteAsync($"api/clients/{Uri.EscapeDataString(clientIdOrPublicId)}/users/{Uri.EscapeDataString(userId)}");
            return response.IsSuccessStatusCode;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error removing user {User} from client {Client}", userId, clientIdOrPublicId);
            return false;
        }
    }
}
