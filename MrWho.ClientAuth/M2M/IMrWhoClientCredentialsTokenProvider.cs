namespace MrWho.ClientAuth.M2M;

/// <summary>
/// Provides cached client_credentials access tokens.
/// </summary>
public interface IMrWhoClientCredentialsTokenProvider
{
    Task<string> GetAccessTokenAsync(CancellationToken cancellationToken = default);
}
