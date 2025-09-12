using System.Text;
using Microsoft.Extensions.Options;
using MrWho.Models;
using MrWho.Options;

namespace MrWho.Services;

public sealed class SymmetricSecretPolicy : ISymmetricSecretPolicy
{
    private readonly SymmetricSecretPolicyOptions _options;
    private readonly ILogger<SymmetricSecretPolicy> _logger;

    public SymmetricSecretPolicy(IOptions<SymmetricSecretPolicyOptions> options, ILogger<SymmetricSecretPolicy> logger)
    { _options = options.Value; _logger = logger; }

    public SymmetricSecretValidationResult ValidateForAlgorithm(string algorithm, string? secret)
    {
        if (string.IsNullOrWhiteSpace(algorithm)) return SymmetricSecretValidationResult.Fail("algorithm_missing");
        algorithm = algorithm.ToUpperInvariant();
        if (secret == null) return SymmetricSecretValidationResult.Fail("secret_missing");
        var length = Encoding.UTF8.GetByteCount(secret);
        int required = algorithm switch
        {
            "HS256" => _options.HS256MinBytes,
            "HS384" => _options.HS384MinBytes,
            "HS512" => _options.HS512MinBytes,
            _ => 0
        };
        if (required == 0) return SymmetricSecretValidationResult.Ok(); // not an enforced alg
        if (length < required)
            return SymmetricSecretValidationResult.Fail($"secret_length_insufficient:{algorithm}", required, length);
        return SymmetricSecretValidationResult.Ok();
    }

    public SymmetricSecretValidationResult ValidateClientMutation(Client client)
    {
        if (!_options.EnforceOnClientMutation) return SymmetricSecretValidationResult.Ok();
        if (client is null) return SymmetricSecretValidationResult.Fail("client_null");
        if (string.IsNullOrWhiteSpace(client.ClientSecret)) return SymmetricSecretValidationResult.Ok(); // allow empty; other validators decide requirement

        // Inspect AllowedRequestObjectAlgs for HMAC usages (JAR)
        var algsCsv = client.AllowedRequestObjectAlgs;
        if (!string.IsNullOrWhiteSpace(algsCsv))
        {
            foreach (var alg in algsCsv.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                if (alg.StartsWith("HS", StringComparison.OrdinalIgnoreCase))
                {
                    var res = ValidateForAlgorithm(alg, client.ClientSecret);
                    if (!res.Success)
                        return res;
                }
            }
        }
        return SymmetricSecretValidationResult.Ok();
    }
}
