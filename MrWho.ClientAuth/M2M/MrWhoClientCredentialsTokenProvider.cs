using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace MrWho.ClientAuth.M2M;

internal sealed class MrWhoClientCredentialsTokenProvider : IMrWhoClientCredentialsTokenProvider
{
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly MrWhoClientCredentialsOptions _options;
    private readonly ILogger<MrWhoClientCredentialsTokenProvider> _logger;

    private string? _accessToken;
    private DateTimeOffset _expiresUtc;

    public MrWhoClientCredentialsTokenProvider(
        IHttpClientFactory httpClientFactory,
        IOptions<MrWhoClientCredentialsOptions> options,
        ILogger<MrWhoClientCredentialsTokenProvider> logger)
    {
        _httpClientFactory = httpClientFactory;
        _options = options.Value;
        _logger = logger;
    }

    public async Task<string> GetAccessTokenAsync(CancellationToken cancellationToken = default)
    {
        if (!string.IsNullOrEmpty(_accessToken) && DateTimeOffset.UtcNow < _expiresUtc)
        {
            return _accessToken!;
        }

        var client = _httpClientFactory.CreateClient(MrWhoClientAuthDefaults.TokenHttpClientName);
        var tokenEndpoint = new Uri(new Uri(_options.Authority.TrimEnd('/')), _options.TokenEndpointPath.TrimStart('/'));

        var form = new Dictionary<string, string>
        {
            ["grant_type"] = "client_credentials",
            ["client_id"] = _options.ClientId,
            ["client_secret"] = _options.ClientSecret,
            ["scope"] = string.Join(' ', _options.Scopes ?? Array.Empty<string>())
        };

        using var response = await client.PostAsync(tokenEndpoint, new FormUrlEncodedContent(form), cancellationToken);
        if (!response.IsSuccessStatusCode)
        {
            var body = await response.Content.ReadAsStringAsync(cancellationToken);
            _logger.LogError("MrWho M2M token request failed: {Status} {Body}", (int)response.StatusCode, body);
            throw new InvalidOperationException($"Token request failed: {(int)response.StatusCode} {response.ReasonPhrase}");
        }

        var json = await response.Content.ReadAsStringAsync(cancellationToken);
        using var doc = JsonDocument.Parse(json);
        _accessToken = doc.RootElement.GetProperty("access_token").GetString();
        if (string.IsNullOrEmpty(_accessToken))
        {
            throw new InvalidOperationException("No access_token in response");
        }
        var expiresIn = doc.RootElement.TryGetProperty("expires_in", out var expProp) ? expProp.GetInt32() : 3600;
        _expiresUtc = DateTimeOffset.UtcNow.AddSeconds(expiresIn) - _options.RefreshSkew;

        _logger.LogDebug("Fetched new MrWho M2M token (len={Len}) exp={Exp}", _accessToken.Length, _expiresUtc);
        return _accessToken!;
    }
}
