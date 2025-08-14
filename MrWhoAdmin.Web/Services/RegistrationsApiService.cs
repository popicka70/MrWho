using System.Net.Http.Json;
using MrWho.Shared.Models;

namespace MrWhoAdmin.Web.Services;

public interface IRegistrationsApiService
{
    Task<List<PendingUserDto>> GetPendingAsync();
    Task<bool> ApproveAsync(string userId);
    Task<bool> RejectAsync(string userId);
}

public class RegistrationsApiService(HttpClient http) : IRegistrationsApiService
{
    private readonly HttpClient _http = http;

    public async Task<List<PendingUserDto>> GetPendingAsync()
    {
        var list = await _http.GetFromJsonAsync<List<PendingUserDto>>("api/registrations/pending");
        return list ?? new();
    }

    public async Task<bool> ApproveAsync(string userId)
    {
        var response = await _http.PostAsync($"api/registrations/{userId}/approve", null);
        return response.IsSuccessStatusCode;
    }

    public async Task<bool> RejectAsync(string userId)
    {
        var response = await _http.PostAsync($"api/registrations/{userId}/reject", null);
        return response.IsSuccessStatusCode;
    }
}
