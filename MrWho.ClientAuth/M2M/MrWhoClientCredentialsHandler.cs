using System.Net.Http;
using Microsoft.Extensions.Logging;

namespace MrWho.ClientAuth.M2M;

/// <summary>
/// Delegating handler that attaches a cached client_credentials access token obtained
/// via <see cref="IMrWhoClientCredentialsTokenProvider"/>.
/// </summary>
internal sealed class MrWhoClientCredentialsHandler : DelegatingHandler
{
    private readonly IMrWhoClientCredentialsTokenProvider _provider;
    private readonly ILogger<MrWhoClientCredentialsHandler> _logger;

    public MrWhoClientCredentialsHandler(IMrWhoClientCredentialsTokenProvider provider, ILogger<MrWhoClientCredentialsHandler> logger)
    {
        _provider = provider;
        _logger = logger;
    }

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var token = await _provider.GetAccessTokenAsync(cancellationToken);
        request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);
        _logger.LogTrace("Attached MrWho M2M access token");
        return await base.SendAsync(request, cancellationToken);
    }
}
