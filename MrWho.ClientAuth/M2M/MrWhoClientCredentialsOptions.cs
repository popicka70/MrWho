namespace MrWho.ClientAuth.M2M;

/// <summary>
/// Options for obtaining machine-to-machine (client_credentials) access tokens
/// via the MrWho identity server.
/// </summary>
public sealed class MrWhoClientCredentialsOptions
{
    /// <summary>
    /// Authority (base address) of the MrWho identity server, e.g. https://localhost:7113
    /// </summary>
    public string Authority { get; set; } = "https://localhost:7113";

    /// <summary>
    /// Relative token endpoint path. Defaults to /connect/token
    /// </summary>
    public string TokenEndpointPath { get; set; } = "/connect/token";

    /// <summary>
    /// Client identifier registered at the server.
    /// </summary>
    public string ClientId { get; set; } = string.Empty;

    /// <summary>
    /// Client secret (required for confidential/machine clients).
    /// </summary>
    public string ClientSecret { get; set; } = string.Empty;

    /// <summary>
    /// Scopes to request (space separated; joined automatically). Optional.
    /// </summary>
    public string[] Scopes { get; set; } = Array.Empty<string>();

    /// <summary>
    /// Refresh skew deducted from expires_in to pre-empt expiry.
    /// </summary>
    public TimeSpan RefreshSkew { get; set; } = TimeSpan.FromSeconds(30);

    /// <summary>
    /// Trust any server certificate (development only!).
    /// </summary>
    public bool AcceptAnyServerCertificate { get; set; } = false;
}
