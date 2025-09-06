using System.Text;
using System.Text.Json;
using MrWho.Shared.Models;

namespace MrWhoAdmin.Web.Services;

public class ClientsApiService : IClientsApiService
{
    private readonly HttpClient _httpClient;
    private readonly ILogger<ClientsApiService> _logger;
    private readonly JsonSerializerOptions _jsonOptions;

    public ClientsApiService(HttpClient httpClient, ILogger<ClientsApiService> logger)
    {
        _httpClient = httpClient;
        _logger = logger;
        _jsonOptions = new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            PropertyNameCaseInsensitive = true
        };
        
        // Log HttpClient configuration for debugging
        _logger.LogInformation("ClientsApiService initialized with BaseAddress: {BaseAddress}", _httpClient.BaseAddress);
    }

    public async Task<PagedResult<ClientDto>?> GetClientsAsync(int page = 1, int pageSize = 10, string? search = null, string? realmId = null)
    {
        try
        {
            var queryString = $"?page={page}&pageSize={pageSize}";
            if (!string.IsNullOrWhiteSpace(search))
            {
                queryString += $"&search={Uri.EscapeDataString(search)}";
            }
            if (!string.IsNullOrWhiteSpace(realmId))
            {
                queryString += $"&realmId={Uri.EscapeDataString(realmId)}";
            }

            var requestUri = $"api/clients{queryString}";
            var fullUri = new Uri(_httpClient.BaseAddress!, requestUri);
            
            _logger.LogInformation("Making request to: {FullUri}", fullUri);
            _logger.LogDebug("Request headers: {Headers}", 
                string.Join(", ", _httpClient.DefaultRequestHeaders.Select(h => $"{h.Key}={string.Join(",", h.Value)}")));

            var response = await _httpClient.GetAsync(requestUri);
            
            _logger.LogInformation("Response Status: {StatusCode} for {RequestUri}", response.StatusCode, fullUri);
            
            if (!response.IsSuccessStatusCode)
            {
                var errorContent = await response.Content.ReadAsStringAsync();
                _logger.LogError("API Error - Status: {StatusCode}, Content: {ErrorContent}", response.StatusCode, errorContent);
                
                // Log response headers for debugging
                _logger.LogDebug("Response headers: {Headers}", 
                    string.Join(", ", response.Headers.Select(h => $"{h.Key}={string.Join(",", h.Value)}")));
                
                return null;
            }

            var json = await response.Content.ReadAsStringAsync();
            _logger.LogDebug("Response content length: {Length}", json.Length);
            
            var result = JsonSerializer.Deserialize<PagedResult<ClientDto>>(json, _jsonOptions);
            _logger.LogInformation("Successfully deserialized {ItemCount} clients", result?.Items.Count ?? 0);
            return result;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting clients");
            return null;
        }
    }

    public async Task<ClientDto?> GetClientAsync(string id)
    {
        try
        {
            var response = await _httpClient.GetAsync($"api/clients/{id}");
            response.EnsureSuccessStatusCode();

            var json = await response.Content.ReadAsStringAsync();
            return JsonSerializer.Deserialize<ClientDto>(json, _jsonOptions);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting client {ClientId}", id);
            return null;
        }
    }

    public async Task<ClientDto?> CreateClientAsync(CreateClientRequest request)
    {
        try
        {
            var json = JsonSerializer.Serialize(request, _jsonOptions);
            var content = new StringContent(json, Encoding.UTF8, "application/json");

            var response = await _httpClient.PostAsync("api/clients", content);
            response.EnsureSuccessStatusCode();

            var responseJson = await response.Content.ReadAsStringAsync();
            return JsonSerializer.Deserialize<ClientDto>(responseJson, _jsonOptions);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error creating client");
            return null;
        }
    }

    public async Task<ClientDto?> UpdateClientAsync(string id, UpdateClientRequest request)
    {
        try
        {
            var json = JsonSerializer.Serialize(request, _jsonOptions);
            var content = new StringContent(json, Encoding.UTF8, "application/json");

            var response = await _httpClient.PutAsync($"api/clients/{id}", content);
            response.EnsureSuccessStatusCode();

            var responseJson = await response.Content.ReadAsStringAsync();
            return JsonSerializer.Deserialize<ClientDto>(responseJson, _jsonOptions);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error updating client {ClientId}", id);
            return null;
        }
    }

    public async Task<bool> DeleteClientAsync(string id)
    {
        try
        {
            var response = await _httpClient.DeleteAsync($"api/clients/{id}");
            return response.IsSuccessStatusCode;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error deleting client {ClientId}", id);
            return false;
        }
    }

    public async Task<ClientDto?> ToggleClientAsync(string id)
    {
        try
        {
            var response = await _httpClient.PostAsync($"api/clients/{id}/toggle", new StringContent(string.Empty));
            response.EnsureSuccessStatusCode();

            var json = await response.Content.ReadAsStringAsync();
            return JsonSerializer.Deserialize<ClientDto>(json, _jsonOptions);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error toggling client {ClientId}", id);
            return null;
        }
    }

    public async Task<ClientExportDto?> ExportClientAsync(string id)
    {
        try
        {
            var response = await _httpClient.GetAsync($"api/clients/{id}/export");
            response.EnsureSuccessStatusCode();
            var json = await response.Content.ReadAsStringAsync();
            return JsonSerializer.Deserialize<ClientExportDto>(json, _jsonOptions);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error exporting client {ClientId}", id);
            return null;
        }
    }

    public async Task<ClientImportResult?> ImportClientAsync(ClientExportDto dto)
    {
        try
        {
            var json = JsonSerializer.Serialize(dto, _jsonOptions);
            var content = new StringContent(json, Encoding.UTF8, "application/json");
            var response = await _httpClient.PostAsync("api/clients/import", content);
            response.EnsureSuccessStatusCode();
            var responseJson = await response.Content.ReadAsStringAsync();
            return JsonSerializer.Deserialize<ClientImportResult>(responseJson, _jsonOptions);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error importing client {ClientId}", dto.ClientId);
            return null;
        }
    }

    // Client-centric identity provider links
    public async Task<List<ClientIdentityProviderDto>> GetIdentityLinksAsync(string clientId)
    {
        try
        {
            var resp = await _httpClient.GetAsync($"api/clients/{clientId}/identity-providers");
            if (!resp.IsSuccessStatusCode)
            {
                _logger.LogWarning("GetIdentityLinks failed for client {ClientId}. Status: {Status}", clientId, resp.StatusCode);
                return new();
            }
            var json = await resp.Content.ReadAsStringAsync();
            return JsonSerializer.Deserialize<List<ClientIdentityProviderDto>>(json, _jsonOptions) ?? new();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "GetIdentityLinksAsync failed for client {ClientId}", clientId);
            return new();
        }
    }

    public async Task<ClientIdentityProviderDto?> AddIdentityLinkAsync(string clientId, string providerId, ClientIdentityProviderDto? dto = null)
    {
        try
        {
            var resp = await _httpClient.PostAsJsonAsync($"api/clients/{clientId}/identity-providers/{providerId}", dto ?? new ClientIdentityProviderDto());
            if (!resp.IsSuccessStatusCode)
            {
                var content = await resp.Content.ReadAsStringAsync();
                _logger.LogWarning("AddIdentityLink failed for client {ClientId} provider {ProviderId}. Status: {Status} Content: {Content}", clientId, providerId, resp.StatusCode, content);
                return null;
            }
            var json = await resp.Content.ReadAsStringAsync();
            return JsonSerializer.Deserialize<ClientIdentityProviderDto>(json, _jsonOptions);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "AddIdentityLinkAsync failed for client {ClientId} -> provider {ProviderId}", clientId, providerId);
            return null;
        }
    }

    public async Task<bool> RemoveIdentityLinkAsync(string clientId, string linkId)
    {
        try
        {
            var resp = await _httpClient.DeleteAsync($"api/clients/{clientId}/identity-providers/{linkId}");
            return resp.IsSuccessStatusCode;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "RemoveIdentityLinkAsync failed for client {ClientId} link {LinkId}", clientId, linkId);
            return false;
        }
    }

    public async Task<(bool ok, string? secret)> RotateSecretAsync(string id, string? newSecret = null, DateTime? expiresAtUtc = null, bool retireOld = true)
    {
        try
        {
            var payload = new RotateClientSecretRequest { NewSecret = newSecret, ExpiresAtUtc = expiresAtUtc, RetireOld = retireOld };
            var json = JsonSerializer.Serialize(payload, _jsonOptions);
            var content = new StringContent(json, Encoding.UTF8, "application/json");
            var resp = await _httpClient.PostAsync($"api/clients/{id}/rotate-secret", content);
            if (!resp.IsSuccessStatusCode)
            {
                var err = await resp.Content.ReadAsStringAsync();
                _logger.LogWarning("RotateSecret failed for {Id}: {Status} {Body}", id, resp.StatusCode, err);
                return (false, null);
            }
            var respJson = await resp.Content.ReadAsStringAsync();
            using var doc = JsonDocument.Parse(respJson);
            var secret = doc.RootElement.TryGetProperty("secret", out var s) ? s.GetString() : null;
            return (true, secret);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "RotateSecretAsync failed for client {Id}", id);
            return (false, null);
        }
    }
}