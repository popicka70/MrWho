namespace MrWho.ClientAuth.Par;

/// <summary>
/// Strongly typed authorization request parameters for PAR (and direct front-channel fallback).
/// Only standard core parameters included; extra parameters can be supplied via Extra.
/// </summary>
public sealed class AuthorizationRequest
{
    public required string ClientId { get; set; }
    public required string RedirectUri { get; set; }
    public string? Scope { get; set; }
    public string ResponseType { get; set; } = "code";
    public string? State { get; set; }
    public string? CodeChallenge { get; set; }
    public string? CodeChallengeMethod { get; set; } = "S256";
    public string? RequestObjectJwt { get; set; } // optional JAR value ("request" param)
    public string? Nonce { get; set; } // NEW
    public string? ClientSecret { get; set; } // NEW: for confidential clients
    public bool UseBasicAuth { get; set; } = true; // NEW: prefer client_secret_basic by default when secret provided
    public Dictionary<string, string> Extra { get; } = new(StringComparer.OrdinalIgnoreCase);
    // Helper to copy from JAR model
    public static AuthorizationRequest FromJar(Jar.JarRequest jar)
    {
        var ar = new AuthorizationRequest
        {
            ClientId = jar.ClientId,
            RedirectUri = jar.RedirectUri,
            Scope = jar.Scope,
            ResponseType = jar.ResponseType,
            State = jar.State,
            CodeChallenge = jar.CodeChallenge,
            CodeChallengeMethod = jar.CodeChallengeMethod,
            Nonce = jar.Nonce // NEW
        };
        foreach (var kv in jar.Extra) ar.Extra[kv.Key] = kv.Value;
        return ar;
    }
}

/// <summary>
/// Result returned by a PAR push.
/// </summary>
public sealed class ParResult
{
    public required string RequestUri { get; init; }
    public required int ExpiresIn { get; init; }
    public DateTimeOffset ReceivedAt { get; init; } = DateTimeOffset.UtcNow;
    public DateTimeOffset ExpiresAt => ReceivedAt.AddSeconds(ExpiresIn);
}

public sealed class ParError
{
    public required string Error { get; init; }
    public string? ErrorDescription { get; init; }
    public int StatusCode { get; init; }
}

public sealed class ParClientOptions
{
    /// <summary>PAR endpoint absolute URI (e.g. https://authority/connect/par)</summary>
    public required Uri ParEndpoint { get; set; }
    /// <summary>Authorize endpoint (for building final redirect). If null: ParEndpoint root + /connect/authorize</summary>
    public Uri? AuthorizeEndpoint { get; set; }
    /// <summary>Timeout for HTTP calls.</summary>
    public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(10);
    /// <summary>If true, fallback to front-channel when PAR disabled error returned.</summary>
    public bool FallbackWhenDisabled { get; set; } = true;
    /// <summary>Auto push if serialized query length would exceed threshold (chars). 0 disables.</summary>
    public int AutoPushQueryLengthThreshold { get; set; } = 1400; // below typical browser limits (~2k) headroom
    /// <summary>If true and a JAR signer is registered, automatically create request object before pushing.</summary>
    public bool AutoJar { get; set; } = true;
}

public interface IPushedAuthorizationService
{
    Task<(ParResult? Result, ParError? Error)> PushAsync(AuthorizationRequest request, CancellationToken ct = default);
    Task<Uri> BuildAuthorizeUrlAsync(AuthorizationRequest request, CancellationToken ct = default);
}
