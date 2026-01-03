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

    /// <summary>
    /// Calls GET /identity on the demo API and returns the response.
    /// The returned identity will have type="user" and show the OBO (on-behalf-of) flow was used.
    /// </summary>
    public async Task<OboApiResponse?> GetIdentityAsync(CancellationToken ct = default)
    {
        using var response = await _httpClient.GetAsync("identity", ct);
        if (!response.IsSuccessStatusCode)
        {
            _logger.LogWarning("OBO API call failed: {StatusCode}", response.StatusCode);
            return null;
        }
        return await response.Content.ReadFromJsonAsync<OboApiResponse>(ct);
    }

    /// <summary>
    /// Backward compatibility method - calls GetIdentityAsync.
    /// </summary>
    [Obsolete("Use GetIdentityAsync instead")]
    public Task<OboApiResponse?> GetProfileAsync(CancellationToken ct = default) =>
        GetIdentityAsync(ct);

    public sealed record OboApiResponse(
        string? Type,
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
