using System.Net.Http.Json;
using System.Text.Json;

namespace MrWhoAdmin.Web.Services;

public interface IClientRegistrationsApiService
{
    Task<PendingClientRegistrationsPage> GetPendingAsync(int page = 1, int pageSize = 20);
    Task<PendingClientRegistrationDetails?> GetAsync(string id);
    Task<ApprovalResult?> ApproveAsync(string id);
    Task<bool> RejectAsync(string id, string? reason = null);
}

public class ClientRegistrationsApiService(HttpClient http, ILogger<ClientRegistrationsApiService> logger) : IClientRegistrationsApiService
{
    private readonly HttpClient _http = http;
    private readonly ILogger<ClientRegistrationsApiService> _logger = logger;
    private readonly JsonSerializerOptions _json = new() { PropertyNameCaseInsensitive = true };

    public async Task<PendingClientRegistrationsPage> GetPendingAsync(int page = 1, int pageSize = 20)
    {
        var url = $"api/client-registrations/pending?page={page}&pageSize={pageSize}";
        var resp = await _http.GetAsync(url);
        if (!resp.IsSuccessStatusCode)
        {
            var text = await resp.Content.ReadAsStringAsync();
            _logger.LogWarning("GetPending failed: {Status} {Body}", resp.StatusCode, text);
            return new PendingClientRegistrationsPage();
        }
        var json = await resp.Content.ReadAsStringAsync();
        return JsonSerializer.Deserialize<PendingClientRegistrationsPage>(json, _json) ?? new();
    }

    public async Task<PendingClientRegistrationDetails?> GetAsync(string id)
    {
        var resp = await _http.GetAsync($"api/client-registrations/{id}");
        if (!resp.IsSuccessStatusCode)
        {
            _logger.LogWarning("Get registration {Id} failed: {Status}", id, resp.StatusCode);
            return null;
        }
        var json = await resp.Content.ReadAsStringAsync();
        return JsonSerializer.Deserialize<PendingClientRegistrationDetails>(json, _json);
    }

    public async Task<ApprovalResult?> ApproveAsync(string id)
    {
        var resp = await _http.PostAsync($"api/client-registrations/{id}/approve", null);
        if (!resp.IsSuccessStatusCode)
        {
            var text = await resp.Content.ReadAsStringAsync();
            _logger.LogWarning("Approve {Id} failed: {Status} {Body}", id, resp.StatusCode, text);
            return null;
        }
        var json = await resp.Content.ReadAsStringAsync();
        return JsonSerializer.Deserialize<ApprovalResult>(json, _json);
    }

    public async Task<bool> RejectAsync(string id, string? reason = null)
    {
        var resp = await _http.PostAsJsonAsync($"api/client-registrations/{id}/reject", new { reason });
        return resp.IsSuccessStatusCode;
    }
}

// DTOs (local to admin web)
public class PendingClientRegistrationsPage
{
    public int Total { get; set; }
    public int Page { get; set; }
    public int PageSize { get; set; }
    public List<PendingClientRegistrationItem> Items { get; set; } = new();
}

public class PendingClientRegistrationItem
{
    public string Id { get; set; } = string.Empty;
    public DateTime SubmittedAt { get; set; }
    public string? SubmittedByUserName { get; set; }
    public string? ClientName { get; set; }
    public string? TokenEndpointAuthMethod { get; set; }
    public string? Scope { get; set; }
    public string? RedirectUris { get; set; }
}

public class PendingClientRegistrationDetails
{
    public string Id { get; set; } = string.Empty;
    public string Status { get; set; } = string.Empty;
    public DateTime SubmittedAt { get; set; }
    public string? SubmittedByUserId { get; set; }
    public string? SubmittedByUserName { get; set; }
    public DateTime? ReviewedAt { get; set; }
    public string? ReviewedBy { get; set; }
    public string? ReviewReason { get; set; }
    public string? ClientName { get; set; }
    public string? TokenEndpointAuthMethod { get; set; }
    public string? Scope { get; set; }
    public string? RedirectUrisCsv { get; set; }
    public DynamicClientRegistrationRequestDto? Request { get; set; }
}

public class DynamicClientRegistrationRequestDto
{
    public string? ClientName { get; set; }
    public List<string>? RedirectUris { get; set; }
    public List<string>? PostLogoutRedirectUris { get; set; }
    public List<string>? GrantTypes { get; set; }
    public List<string>? ResponseTypes { get; set; }
    public string? Scope { get; set; }
    public string? TokenEndpointAuthMethod { get; set; }
    public string? ApplicationType { get; set; }
    public string? ClientUri { get; set; }
    public string? LogoUri { get; set; }
}

public class ApprovalResult
{
    public string Id { get; set; } = string.Empty;
    public string Status { get; set; } = string.Empty;
    public string? Client_Id { get; set; } // Allow snake_case mapping if server returns it
    public string? ClientId { get; set; } // for case-insensitive mapping
    public string? Client_Secret { get; set; } // snake_case
    public string? ClientSecret { get; set; }
}
