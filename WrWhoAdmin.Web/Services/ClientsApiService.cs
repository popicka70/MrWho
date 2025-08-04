using System.Text;
using System.Text.Json;
using MrWhoAdmin.Web.Models;

namespace MrWhoAdmin.Web.Services;

/// <summary>
/// Service for managing clients via MrWho API
/// </summary>
public interface IClientsApiService
{
    Task<PagedResult<ClientDto>?> GetClientsAsync(int page = 1, int pageSize = 10, string? search = null, string? realmId = null);
    Task<ClientDto?> GetClientAsync(string id);
    Task<ClientDto?> CreateClientAsync(CreateClientRequest request);
    Task<ClientDto?> UpdateClientAsync(string id, CreateClientRequest request);
    Task<bool> DeleteClientAsync(string id);
    Task<ClientDto?> ToggleClientAsync(string id);
}

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
        catch (HttpRequestException httpEx)
        {
            _logger.LogError(httpEx, "HTTP request exception getting clients. BaseAddress: {BaseAddress}", _httpClient.BaseAddress);
            return null;
        }
        catch (TaskCanceledException tcEx)
        {
            _logger.LogError(tcEx, "Request timeout getting clients. BaseAddress: {BaseAddress}", _httpClient.BaseAddress);
            return null;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting clients. BaseAddress: {BaseAddress}", _httpClient.BaseAddress);
            return null;
        }
    }

    public async Task<ClientDto?> GetClientAsync(string id)
    {
        try
        {
            var requestUri = $"api/clients/{id}";
            var fullUri = new Uri(_httpClient.BaseAddress!, requestUri);
            
            _logger.LogInformation("Getting client {ClientId} from: {FullUri}", id, fullUri);
            
            var response = await _httpClient.GetAsync(requestUri);
            
            if (!response.IsSuccessStatusCode)
            {
                var errorContent = await response.Content.ReadAsStringAsync();
                _logger.LogError("API Error getting client {ClientId} - Status: {StatusCode}, Content: {ErrorContent}", 
                    id, response.StatusCode, errorContent);
                return null;
            }

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
            // Convert the request to match the API's expectations (enum as integer)
            var apiCompatibleRequest = new
            {
                clientId = request.ClientId,
                clientSecret = request.ClientSecret,
                name = request.Name,
                description = request.Description,
                realmId = request.RealmId,
                isEnabled = request.IsEnabled,
                clientType = (int)request.ClientType, // Convert enum to integer
                allowAuthorizationCodeFlow = request.AllowAuthorizationCodeFlow,
                allowClientCredentialsFlow = request.AllowClientCredentialsFlow,
                allowPasswordFlow = request.AllowPasswordFlow,
                allowRefreshTokenFlow = request.AllowRefreshTokenFlow,
                requirePkce = request.RequirePkce,
                requireClientSecret = request.RequireClientSecret,
                accessTokenLifetime = request.AccessTokenLifetime,
                refreshTokenLifetime = request.RefreshTokenLifetime,
                authorizationCodeLifetime = request.AuthorizationCodeLifetime,
                redirectUris = request.RedirectUris,
                postLogoutUris = request.PostLogoutUris,
                scopes = request.Scopes,
                permissions = request.Permissions
            };

            var json = JsonSerializer.Serialize(apiCompatibleRequest, _jsonOptions);
            var content = new StringContent(json, Encoding.UTF8, "application/json");

            _logger.LogInformation("Creating client {ClientId}", request.ClientId);
            _logger.LogInformation("Request payload for debugging: {Payload}", json);

            var response = await _httpClient.PostAsync("api/clients", content);
            
            if (!response.IsSuccessStatusCode)
            {
                var errorContent = await response.Content.ReadAsStringAsync();
                _logger.LogError("API Error creating client - Status: {StatusCode}, Content: {ErrorContent}", 
                    response.StatusCode, errorContent);
                return null;
            }

            var responseJson = await response.Content.ReadAsStringAsync();
            _logger.LogInformation("Successful client creation response: {Response}", responseJson);
            return JsonSerializer.Deserialize<ClientDto>(responseJson, _jsonOptions);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error creating client");
            return null;
        }
    }

    public async Task<ClientDto?> UpdateClientAsync(string id, CreateClientRequest request)
    {
        try
        {
            // Convert CreateClientRequest to UpdateClientRequest for the API with integer enum
            var updateRequest = new
            {
                clientSecret = request.ClientSecret,
                name = request.Name,
                description = request.Description,
                isEnabled = request.IsEnabled,
                clientType = (int?)request.ClientType, // Convert enum to integer
                allowAuthorizationCodeFlow = request.AllowAuthorizationCodeFlow,
                allowClientCredentialsFlow = request.AllowClientCredentialsFlow,
                allowPasswordFlow = request.AllowPasswordFlow,
                allowRefreshTokenFlow = request.AllowRefreshTokenFlow,
                requirePkce = request.RequirePkce,
                requireClientSecret = request.RequireClientSecret,
                accessTokenLifetime = request.AccessTokenLifetime,
                refreshTokenLifetime = request.RefreshTokenLifetime,
                authorizationCodeLifetime = request.AuthorizationCodeLifetime,
                redirectUris = request.RedirectUris,
                postLogoutUris = request.PostLogoutUris,
                scopes = request.Scopes,
                permissions = request.Permissions
            };

            var json = JsonSerializer.Serialize(updateRequest, _jsonOptions);
            var content = new StringContent(json, Encoding.UTF8, "application/json");

            _logger.LogInformation("Updating client {ClientId}", id);
            _logger.LogDebug("Request payload: {Payload}", json);

            var response = await _httpClient.PutAsync($"api/clients/{id}", content);
            
            if (!response.IsSuccessStatusCode)
            {
                var errorContent = await response.Content.ReadAsStringAsync();
                _logger.LogError("API Error updating client {ClientId} - Status: {StatusCode}, Content: {ErrorContent}", 
                    id, response.StatusCode, errorContent);
                return null;
            }

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
            _logger.LogInformation("Deleting client {ClientId}", id);
            
            var response = await _httpClient.DeleteAsync($"api/clients/{id}");
            
            if (!response.IsSuccessStatusCode)
            {
                var errorContent = await response.Content.ReadAsStringAsync();
                _logger.LogError("API Error deleting client {ClientId} - Status: {StatusCode}, Content: {ErrorContent}", 
                    id, response.StatusCode, errorContent);
            }
            
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
            _logger.LogInformation("Toggling client {ClientId}", id);
            
            var response = await _httpClient.PostAsync($"api/clients/{id}/toggle", null);
            
            if (!response.IsSuccessStatusCode)
            {
                var errorContent = await response.Content.ReadAsStringAsync();
                _logger.LogError("API Error toggling client {ClientId} - Status: {StatusCode}, Content: {ErrorContent}", 
                    id, response.StatusCode, errorContent);
                return null;
            }

            var responseJson = await response.Content.ReadAsStringAsync();
            return JsonSerializer.Deserialize<ClientDto>(responseJson, _jsonOptions);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error toggling client {ClientId}", id);
            return null;
        }
    }
}