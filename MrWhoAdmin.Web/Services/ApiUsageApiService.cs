using System.Net.Http.Headers;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using MrWho.Shared.Models;

namespace MrWhoAdmin.Web.Services;

public class ApiUsageApiService : IApiUsageApiService
{
    private readonly HttpClient _httpClient;
    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly ILogger<ApiUsageApiService> _logger;
    private readonly JsonSerializerOptions _jsonOptions;

    public ApiUsageApiService(HttpClient httpClient, IHttpContextAccessor httpContextAccessor, ILogger<ApiUsageApiService> logger)
    {
        _httpClient = httpClient;
        _httpContextAccessor = httpContextAccessor;
        _logger = logger;
        _jsonOptions = new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            PropertyNameCaseInsensitive = true
        };
    }

    public async Task<ApiUsageOverviewDto?> GetOverviewAsync(CancellationToken ct = default)
    {
        try
        {
            await SetAuthorizationHeaderAsync();
            var resp = await _httpClient.GetAsync("api/monitoring/usage/overview", ct);
            if (!resp.IsSuccessStatusCode) return null;
            var json = await resp.Content.ReadAsStringAsync(ct);
            return JsonSerializer.Deserialize<ApiUsageOverviewDto>(json, _jsonOptions);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "GetOverviewAsync failed");
            return null;
        }
    }

    public async Task<List<ApiUsageTopClientDto>> GetTopClientsAsync(int take = 20, CancellationToken ct = default)
    {
        try
        {
            await SetAuthorizationHeaderAsync();
            var resp = await _httpClient.GetAsync($"api/monitoring/usage/top-clients?take={take}", ct);
            if (!resp.IsSuccessStatusCode) return new();
            var json = await resp.Content.ReadAsStringAsync(ct);
            return JsonSerializer.Deserialize<List<ApiUsageTopClientDto>>(json, _jsonOptions) ?? new();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "GetTopClientsAsync failed");
            return new();
        }
    }

    public async Task<List<ApiEndpointUsageDto>> GetTopEndpointsAsync(int take = 20, CancellationToken ct = default)
    {
        try
        {
            await SetAuthorizationHeaderAsync();
            var resp = await _httpClient.GetAsync($"api/monitoring/usage/top-endpoints?take={take}", ct);
            if (!resp.IsSuccessStatusCode) return new();
            var json = await resp.Content.ReadAsStringAsync(ct);
            return JsonSerializer.Deserialize<List<ApiEndpointUsageDto>>(json, _jsonOptions) ?? new();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "GetTopEndpointsAsync failed");
            return new();
        }
    }

    public async Task<List<ApiUsageTimeSeriesPointDto>> GetTimeSeriesAsync(int days = 14, CancellationToken ct = default)
    {
        try
        {
            await SetAuthorizationHeaderAsync();
            var resp = await _httpClient.GetAsync($"api/monitoring/usage/timeseries?days={days}", ct);
            if (!resp.IsSuccessStatusCode) return new();
            var json = await resp.Content.ReadAsStringAsync(ct);
            return JsonSerializer.Deserialize<List<ApiUsageTimeSeriesPointDto>>(json, _jsonOptions) ?? new();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "GetTimeSeriesAsync failed");
            return new();
        }
    }

    private async Task SetAuthorizationHeaderAsync()
    {
        var context = _httpContextAccessor.HttpContext;
        if (context == null) return;
        var token = await context.GetTokenAsync("access_token");
        if (!string.IsNullOrEmpty(token))
        {
            _httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
        }
    }
}