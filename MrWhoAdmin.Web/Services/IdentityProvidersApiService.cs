using System.Text.Json;
using MrWho.Shared.Models;

namespace MrWhoAdmin.Web.Services;

public interface IIdentityProvidersApiService
{
    Task<List<IdentityProviderDto>> GetIdentityProvidersAsync(string? realmId = null, CancellationToken ct = default);
    Task<IdentityProviderDto?> GetIdentityProviderAsync(string id, CancellationToken ct = default);
    Task<IdentityProviderDto?> CreateIdentityProviderAsync(IdentityProviderDto dto, CancellationToken ct = default);
    Task<IdentityProviderDto?> UpdateIdentityProviderAsync(string id, IdentityProviderDto dto, CancellationToken ct = default);
    // Links
    Task<List<ClientIdentityProviderDto>> GetLinksAsync(string idpId, CancellationToken ct = default);
    Task<ClientIdentityProviderDto?> AddLinkAsync(string idpId, string clientId, ClientIdentityProviderDto? dto = null, CancellationToken ct = default);
    Task<bool> RemoveLinkAsync(string idpId, string linkId, CancellationToken ct = default);
}

public class IdentityProvidersApiService : IIdentityProvidersApiService
{
    private readonly HttpClient _httpClient;
    private readonly ILogger<IdentityProvidersApiService> _logger;
    private readonly JsonSerializerOptions _jsonOptions;

    public IdentityProvidersApiService(HttpClient httpClient, ILogger<IdentityProvidersApiService> logger)
    {
        _httpClient = httpClient;
        _logger = logger;
        _jsonOptions = new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            PropertyNameCaseInsensitive = true
        };

        _logger.LogInformation("IdentityProvidersApiService BaseAddress: {BaseAddress}", _httpClient.BaseAddress);
    }

    public async Task<List<IdentityProviderDto>> GetIdentityProvidersAsync(string? realmId = null, CancellationToken ct = default)
    {
        try
        {
            var uri = string.IsNullOrWhiteSpace(realmId)
                ? "api/IdentityProviders"
                : $"api/IdentityProviders?realmId={Uri.EscapeDataString(realmId)}";

            var resp = await _httpClient.GetAsync(uri, ct);
            if (!resp.IsSuccessStatusCode)
            {
                _logger.LogWarning("Failed to list IdentityProviders. Status: {Status}", resp.StatusCode);
                return new();
            }

            var json = await resp.Content.ReadAsStringAsync(ct);
            return JsonSerializer.Deserialize<List<IdentityProviderDto>>(json, _jsonOptions) ?? new();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "GetIdentityProvidersAsync failed");
            return new();
        }
    }

    public async Task<IdentityProviderDto?> GetIdentityProviderAsync(string id, CancellationToken ct = default)
    {
        try
        {
            var resp = await _httpClient.GetAsync($"api/IdentityProviders/{id}", ct);
            if (!resp.IsSuccessStatusCode)
            {
                _logger.LogWarning("Failed to get IdentityProvider {Id}. Status: {Status}", id, resp.StatusCode);
                return null;
            }
            var json = await resp.Content.ReadAsStringAsync(ct);
            return JsonSerializer.Deserialize<IdentityProviderDto>(json, _jsonOptions);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "GetIdentityProviderAsync failed for {Id}", id);
            return null;
        }
    }

    public async Task<IdentityProviderDto?> CreateIdentityProviderAsync(IdentityProviderDto dto, CancellationToken ct = default)
    {
        try
        {
            var resp = await _httpClient.PostAsJsonAsync("api/IdentityProviders", dto, ct);
            if (!resp.IsSuccessStatusCode)
            {
                var content = await resp.Content.ReadAsStringAsync(ct);
                _logger.LogWarning("CreateIdentityProvider failed. Status: {Status} Content: {Content}", resp.StatusCode, content);
                return null;
            }
            var json = await resp.Content.ReadAsStringAsync(ct);
            return JsonSerializer.Deserialize<IdentityProviderDto>(json, _jsonOptions);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "CreateIdentityProviderAsync failed");
            return null;
        }
    }

    public async Task<IdentityProviderDto?> UpdateIdentityProviderAsync(string id, IdentityProviderDto dto, CancellationToken ct = default)
    {
        try
        {
            var resp = await _httpClient.PutAsJsonAsync($"api/IdentityProviders/{id}", dto, ct);
            if (!resp.IsSuccessStatusCode)
            {
                var content = await resp.Content.ReadAsStringAsync(ct);
                _logger.LogWarning("UpdateIdentityProvider failed. Status: {Status} Content: {Content}", resp.StatusCode, content);
                return null;
            }
            var json = await resp.Content.ReadAsStringAsync(ct);
            return JsonSerializer.Deserialize<IdentityProviderDto>(json, _jsonOptions);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "UpdateIdentityProviderAsync failed for {Id}", id);
            return null;
        }
    }

    public async Task<List<ClientIdentityProviderDto>> GetLinksAsync(string idpId, CancellationToken ct = default)
    {
        try
        {
            var resp = await _httpClient.GetAsync($"api/IdentityProviders/{idpId}/clients", ct);
            if (!resp.IsSuccessStatusCode)
            {
                _logger.LogWarning("GetLinks failed for IdP {Id}. Status: {Status}", idpId, resp.StatusCode);
                return new();
            }
            var json = await resp.Content.ReadAsStringAsync(ct);
            return JsonSerializer.Deserialize<List<ClientIdentityProviderDto>>(json, _jsonOptions) ?? new();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "GetLinksAsync failed for {Id}", idpId);
            return new();
        }
    }

    public async Task<ClientIdentityProviderDto?> AddLinkAsync(string idpId, string clientId, ClientIdentityProviderDto? dto = null, CancellationToken ct = default)
    {
        try
        {
            var resp = await _httpClient.PostAsJsonAsync($"api/IdentityProviders/{idpId}/clients/{clientId}", dto ?? new ClientIdentityProviderDto(), ct);
            if (!resp.IsSuccessStatusCode)
            {
                var content = await resp.Content.ReadAsStringAsync(ct);
                _logger.LogWarning("AddLink failed for IdP {Id} client {Client}. Status: {Status} Content: {Content}", idpId, clientId, resp.StatusCode, content);
                return null;
            }
            var json = await resp.Content.ReadAsStringAsync(ct);
            return JsonSerializer.Deserialize<ClientIdentityProviderDto>(json, _jsonOptions);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "AddLinkAsync failed for {Id} -> {Client}", idpId, clientId);
            return null;
        }
    }

    public async Task<bool> RemoveLinkAsync(string idpId, string linkId, CancellationToken ct = default)
    {
        try
        {
            var resp = await _httpClient.DeleteAsync($"api/IdentityProviders/{idpId}/clients/{linkId}", ct);
            return resp.IsSuccessStatusCode;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "RemoveLinkAsync failed for {Id} link {Link}", idpId, linkId);
            return false;
        }
    }
}
