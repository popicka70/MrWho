using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection; // add for IServiceCollection
using System.Security.Cryptography.X509Certificates;

namespace MrWho.ClientAuth.Jar;

/// <summary>
/// Options for producing JAR (JWT Secured Authorization Request) objects.
/// </summary>
public sealed class JarClientOptions
{
    /// <summary>Issuer to set inside request object (defaults to client_id).</summary>
    public string? Issuer { get; set; }
    /// <summary>Audience / server identifier. If null, derived from Authority host.</summary>
    public string? Audience { get; set; }
    /// <summary>Lifetime for request objects.</summary>
    public TimeSpan Lifetime { get; set; } = TimeSpan.FromMinutes(5);
    /// <summary>Clock skew applied to iat/nbf.</summary>
    public TimeSpan ClockSkew { get; set; } = TimeSpan.FromSeconds(5);
    /// <summary>Signing algorithm. HS256 or RS256 currently.</summary>
    public string Algorithm { get; set; } = SecurityAlgorithms.HmacSha256;
    /// <summary>Symmetric secret for HS algorithms. If null and RS selected, RSA key must be supplied.</summary>
    public string? ClientSecret { get; set; }
    /// <summary>Optional RSA private key (PEM format).</summary>
    public string? RsaPrivateKeyPem { get; set; }
    /// <summary>Optional X509 certificate (with private key) for RS256 signing.</summary>
    public X509Certificate2? RsaCertificate { get; set; }
    /// <summary>Include jti claim.</summary>
    public bool IncludeJti { get; set; } = true;
    /// <summary>Extra static claims.</summary>
    public Dictionary<string, object> StaticClaims { get; } = new();
}

public interface IJarRequestObjectSigner
{
    Task<string> CreateRequestObjectAsync(JarRequest request, CancellationToken ct = default);
}

public sealed class JarRequest
{
    public required string ClientId { get; set; }
    public required string RedirectUri { get; set; }
    public string? Scope { get; set; }
    public string ResponseType { get; set; } = "code";
    public string? State { get; set; }
    public string? CodeChallenge { get; set; }
    public string? CodeChallengeMethod { get; set; } = "S256";
    public Dictionary<string,string> Extra { get; } = new(StringComparer.OrdinalIgnoreCase);
}

internal sealed class JarRequestObjectSigner : IJarRequestObjectSigner
{
    private readonly JarClientOptions _options;
    private readonly Lazy<SigningCredentials> _credsLazy;

    public JarRequestObjectSigner(JarClientOptions options)
    {
        _options = options;
        _credsLazy = new Lazy<SigningCredentials>(CreateCreds, true);
    }

    public Task<string> CreateRequestObjectAsync(JarRequest request, CancellationToken ct = default)
    {
        var now = DateTimeOffset.UtcNow;
        var exp = now.Add(_options.Lifetime);
        var jti = _options.IncludeJti ? Guid.NewGuid().ToString("n") : null;

        var claims = new Dictionary<string, object>
        {
            ["iss"] = _options.Issuer ?? request.ClientId,
            ["aud"] = _options.Audience ?? "mrwho",
            ["client_id"] = request.ClientId,
            ["redirect_uri"] = request.RedirectUri,
            ["response_type"] = request.ResponseType,
            ["iat"] = now.ToUnixTimeSeconds(),
            ["exp"] = exp.ToUnixTimeSeconds(),
            ["nbf"] = now.AddSeconds(-_options.ClockSkew.TotalSeconds).ToUnixTimeSeconds()
        };
        if (!string.IsNullOrWhiteSpace(request.Scope)) claims["scope"] = request.Scope!;
        if (!string.IsNullOrWhiteSpace(request.State)) claims["state"] = request.State!;
        if (!string.IsNullOrWhiteSpace(request.CodeChallenge))
        {
            claims["code_challenge"] = request.CodeChallenge;
            claims["code_challenge_method"] = request.CodeChallengeMethod ?? "S256";
        }
        foreach (var kv in request.Extra)
            claims[kv.Key] = kv.Value;
        foreach (var s in _options.StaticClaims)
            claims[s.Key] = s.Value;
        if (jti != null) claims["jti"] = jti;

        var handler = new Microsoft.IdentityModel.JsonWebTokens.JsonWebTokenHandler();
        var token = handler.CreateToken(new SecurityTokenDescriptor
        {
            Claims = claims,
            Expires = exp.UtcDateTime,
            IssuedAt = now.UtcDateTime,
            NotBefore = now.UtcDateTime.AddSeconds(-_options.ClockSkew.TotalSeconds),
            SigningCredentials = _credsLazy.Value
        });
        return Task.FromResult(token);
    }

    private SigningCredentials CreateCreds()
    {
        if (_options.Algorithm.StartsWith("HS", StringComparison.OrdinalIgnoreCase))
        {
            var secret = _options.ClientSecret;
            if (string.IsNullOrWhiteSpace(secret) || Encoding.UTF8.GetByteCount(secret) < 32)
                throw new InvalidOperationException("ClientSecret must be >=32 bytes for HS algorithms");
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secret));
            return new SigningCredentials(key, _options.Algorithm);
        }
        if (_options.Algorithm.Equals(SecurityAlgorithms.RsaSha256, StringComparison.OrdinalIgnoreCase))
        {
            if (_options.RsaCertificate != null)
            {
                if (!_options.RsaCertificate.HasPrivateKey)
                    throw new InvalidOperationException("Provided certificate does not contain a private key");
                return new SigningCredentials(new X509SecurityKey(_options.RsaCertificate), SecurityAlgorithms.RsaSha256);
            }
            if (!string.IsNullOrWhiteSpace(_options.RsaPrivateKeyPem))
            {
                using var rsa = RSA.Create();
                try { rsa.ImportFromPem(_options.RsaPrivateKeyPem.AsSpan()); }
                catch (Exception ex) { throw new InvalidOperationException("Invalid RSA private key PEM", ex); }
                var key = new RsaSecurityKey(rsa.ExportParameters(includePrivateParameters: true));
                return new SigningCredentials(key, SecurityAlgorithms.RsaSha256);
            }
            throw new InvalidOperationException("RS256 selected but no RsaCertificate or RsaPrivateKeyPem provided");
        }
        throw new NotSupportedException("Unsupported algorithm " + _options.Algorithm);
    }
}

public static class JarServiceCollectionExtensions
{
    public static IServiceCollection AddMrWhoJarSigner(this IServiceCollection services, Action<JarClientOptions> configure)
    {
        var opts = new JarClientOptions();
        configure(opts);
        services.AddSingleton(opts);
        services.AddSingleton<IJarRequestObjectSigner, JarRequestObjectSigner>();
        return services;
    }
}
