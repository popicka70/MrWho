using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.Extensions.Logging;

namespace MrWhoOidc.RazorClient.Services;

/// <summary>
/// HTTP client for calling the OBO Demo API using machine-to-machine (M2M) credentials.
/// Acquires tokens via the client credentials grant and caches them.
/// </summary>
public sealed class M2MApiClient
{
    private readonly HttpClient _httpClient;
    private readonly ILogger<M2MApiClient> _logger;

    public M2MApiClient(HttpClient httpClient, ILogger<M2MApiClient> logger)
    {
        _httpClient = httpClient;
        _logger = logger;
    }

    /// <summary>
    /// Calls GET /identity on the demo API and returns the response.
    /// The returned identity will have type="machine" and show the client credentials grant was used.
    /// </summary>
    public async Task<M2MApiResponse?> GetIdentityAsync(CancellationToken ct = default)
    {
        using var response = await _httpClient.GetAsync("identity", ct);
        if (!response.IsSuccessStatusCode)
        {
            _logger.LogWarning("M2M API call failed: {StatusCode}", response.StatusCode);
            return null;
        }
        return await response.Content.ReadFromJsonAsync<M2MApiResponse>(ct);
    }

    /// <summary>
    /// Response from the M2M API call.
    /// </summary>
    public sealed record M2MApiResponse(
        string? Type,
        string? Message,
        string? ClientId,
        string? Subject,
        string? Audience,
        IEnumerable<string>? Scopes,
        string? IssuedAt,
        string? ExpiresAt);
}
