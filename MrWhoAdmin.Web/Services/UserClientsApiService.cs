using System.Text.Json;
using MrWho.Shared.Models;

namespace MrWhoAdmin.Web.Services;

public class UserClientsApiService : IUserClientsApiService
{
    private readonly HttpClient _httpClient;
    private readonly ILogger<UserClientsApiService> _logger;
    private readonly JsonSerializerOptions _jsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = true
    };

    public UserClientsApiService(HttpClient httpClient, ILogger<UserClientsApiService> logger)
    {
        _httpClient = httpClient;
        _logger = logger;
    }

    public async Task<UserClientsListDto?> GetClientsForUserAsync(string userIdOrNameOrEmail)
    {
        try
        {
            var response = await _httpClient.GetAsync($"api/users/{Uri.EscapeDataString(userIdOrNameOrEmail)}/clients");
            response.EnsureSuccessStatusCode();
            var json = await response.Content.ReadAsStringAsync();
            return JsonSerializer.Deserialize<UserClientsListDto>(json, _jsonOptions);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting clients for user {User}", userIdOrNameOrEmail);
            return null;
        }
    }
}
