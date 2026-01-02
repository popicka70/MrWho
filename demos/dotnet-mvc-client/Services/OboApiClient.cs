using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.Extensions.Logging;

namespace MrWhoOidc.RazorClient.Services;

public sealed class OboApiClient
{
    private readonly HttpClient _httpClient;
    private readonly ILogger<OboApiClient> _logger;

    public OboApiClient(HttpClient httpClient, ILogger<OboApiClient> logger)
    {
        _httpClient = httpClient;
        _logger = logger;
    }

    public async Task<OboApiResponse?> GetProfileAsync(CancellationToken ct = default)
    {
        using var response = await _httpClient.GetAsync("me", ct);
        if (!response.IsSuccessStatusCode)
        {
            _logger.LogWarning("OBO API call failed: {StatusCode}", response.StatusCode);
            return null;
        }
        return await response.Content.ReadFromJsonAsync<OboApiResponse>(ct);
    }

    public sealed record OboApiResponse(
        string? Message,
        string? Subject,
        string? Name,
        string? Email,
        string? Actor,
        string? Audience,
        IEnumerable<string>? Scopes,
        string? IssuedAt,
        string? ExpiresAt,
        JsonElement? UserInfo);
}
