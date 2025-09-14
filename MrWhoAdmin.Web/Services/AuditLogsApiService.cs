using System.Net.Http.Headers;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using MrWho.Shared.Models;

namespace MrWhoAdmin.Web.Services;

public class AuditLogsApiService : IAuditLogsApiService
{
    private readonly HttpClient _httpClient;
    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly ILogger<AuditLogsApiService> _logger;
    private readonly JsonSerializerOptions _jsonOptions;

    public AuditLogsApiService(HttpClient httpClient, IHttpContextAccessor httpContextAccessor, ILogger<AuditLogsApiService> logger)
    {
        _httpClient = httpClient;
        _httpContextAccessor = httpContextAccessor;
        _logger = logger;
        _jsonOptions = new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            WriteIndented = false
        };
    }

    public async Task<PagedResult<AuditLogDto>?> GetAuditLogsAsync(int page = 1, int pageSize = 25, string? search = null, string? entityType = null, string? action = null, DateTime? fromUtc = null, DateTime? toUtc = null)
    {
        try
        {
            await SetAuthorizationHeaderAsync();

            var query = new List<string>
            {
                $"page={page}",
                $"pageSize={pageSize}"
            };
            if (!string.IsNullOrWhiteSpace(search)) {
                query.Add($"search={Uri.EscapeDataString(search)}");
            }

            if (!string.IsNullOrWhiteSpace(entityType)) {
                query.Add($"entityType={Uri.EscapeDataString(entityType)}");
            }

            if (!string.IsNullOrWhiteSpace(action)) {
                query.Add($"action={Uri.EscapeDataString(action)}");
            }

            if (fromUtc.HasValue) {
                query.Add($"fromUtc={Uri.EscapeDataString(fromUtc.Value.ToString("O"))}");
            }

            if (toUtc.HasValue) {
                query.Add($"toUtc={Uri.EscapeDataString(toUtc.Value.ToString("O"))}");
            }

            var url = $"api/auditlogs?{string.Join("&", query)}";
            var response = await _httpClient.GetAsync(url);
            if (response.IsSuccessStatusCode)
            {
                var json = await response.Content.ReadAsStringAsync();
                return JsonSerializer.Deserialize<PagedResult<AuditLogDto>>(json, _jsonOptions);
            }

            _logger.LogWarning("Failed to get audit logs. Status: {Status}, Content: {Content}", response.StatusCode, await response.Content.ReadAsStringAsync());
            return null;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting audit logs");
            return null;
        }
    }

    public async Task<List<string>> GetEntityTypesAsync()
    {
        try
        {
            await SetAuthorizationHeaderAsync();
            var response = await _httpClient.GetAsync("api/auditlogs/entity-types");
            if (response.IsSuccessStatusCode)
            {
                var json = await response.Content.ReadAsStringAsync();
                return JsonSerializer.Deserialize<List<string>>(json, _jsonOptions) ?? new();
            }
            return new();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting audit entity types");
            return new();
        }
    }

    public async Task<List<string>> GetActionsAsync()
    {
        try
        {
            await SetAuthorizationHeaderAsync();
            var response = await _httpClient.GetAsync("api/auditlogs/actions");
            if (response.IsSuccessStatusCode)
            {
                var json = await response.Content.ReadAsStringAsync();
                return JsonSerializer.Deserialize<List<string>>(json, _jsonOptions) ?? new();
            }
            return new();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting audit actions");
            return new();
        }
    }

    private async Task SetAuthorizationHeaderAsync()
    {
        var httpContext = _httpContextAccessor.HttpContext;
        if (httpContext != null)
        {
            var accessToken = await httpContext.GetTokenAsync("access_token");
            if (!string.IsNullOrEmpty(accessToken))
            {
                _httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
            }
        }
    }
}
