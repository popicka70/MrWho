namespace MrWho.ClientAuth.M2M;

/// <summary>
/// Options controlling behavior of <see cref="MrWhoUserAccessTokenHandler"/>.
/// </summary>
public sealed class MrWhoUserAccessTokenHandlerOptions
{
    /// <summary>
    /// When true (default) the handler will attempt to refresh the user's access token automatically
    /// using the refresh_token (if present) when the token is within a skew of expiry.
    /// </summary>
    public bool EnableAutomaticRefresh { get; set; } = true;

    /// <summary>
    /// When true (default) a downstream 401 response will trigger an OpenID Connect challenge (redirect to login)
    /// if the current HttpContext has an authenticated principal.
    /// </summary>
    public bool ChallengeOnUnauthorized { get; set; } = true;

    /// <summary>
    /// Skew window before expiry where refresh will be attempted. Default: 1 minute.
    /// </summary>
    public TimeSpan RefreshSkew { get; set; } = TimeSpan.FromMinutes(1);
}
