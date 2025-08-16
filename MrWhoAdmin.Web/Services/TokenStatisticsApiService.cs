using System.Net.Http.Headers;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using MrWho.Shared.Models;

namespace MrWhoAdmin.Web.Services;

public class TokenStatisticsApiService : ITokenStatisticsApiService
{
    private readonly HttpClient _httpClient;
    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly ILogger<TokenStatisticsApiService> _logger;
    private readonly JsonSerializerOptions _jsonOptions;

    public TokenStatisticsApiService(HttpClient httpClient, IHttpContextAccessor httpContextAccessor, ILogger<TokenStatisticsApiService> logger)
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

    public async Task<TokenStatisticsOverviewDto?> GetOverviewAsync(CancellationToken ct = default)
    {
        try
        {
            await SetAuthorizationHeaderAsync();
            var response = await _httpClient.GetAsync("api/monitoring/tokens/overview", ct);
            if (response.IsSuccessStatusCode)
            {
                var json = await response.Content.ReadAsStringAsync(ct);
                return JsonSerializer.Deserialize<TokenStatisticsOverviewDto>(json, _jsonOptions);
            }
            _logger.LogWarning("Failed to get token overview. Status: {Status}", response.StatusCode);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting token overview");
        }
        return null;
    }

    public async Task<List<TokenClientStatDto>> GetTopClientsAsync(int take = 20, CancellationToken ct = default)
    {
        try
        {
            await SetAuthorizationHeaderAsync();
            var response = await _httpClient.GetAsync($"api/monitoring/tokens/top-clients?take={take}", ct);
            if (response.IsSuccessStatusCode)
            {
                var json = await response.Content.ReadAsStringAsync(ct);
                return JsonSerializer.Deserialize<List<TokenClientStatDto>>(json, _jsonOptions) ?? new();
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting top client token stats");
        }
        return new();
    }

    public async Task<List<TokenTimeSeriesPointDto>> GetTimeSeriesAsync(int days = 14, CancellationToken ct = default)
    {
        try
        {
            await SetAuthorizationHeaderAsync();
            var response = await _httpClient.GetAsync($"api/monitoring/tokens/timeseries?days={days}", ct);
            if (response.IsSuccessStatusCode)
            {
                var json = await response.Content.ReadAsStringAsync(ct);
                return JsonSerializer.Deserialize<List<TokenTimeSeriesPointDto>>(json, _jsonOptions) ?? new();
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting token timeseries");
        }
        return new();
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
