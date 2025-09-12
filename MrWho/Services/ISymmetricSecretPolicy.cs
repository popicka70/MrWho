using MrWho.Models;

namespace MrWho.Services;

public interface ISymmetricSecretPolicy
{
    /// <summary>
    /// Validate a client secret against an HMAC JWS algorithm requirement.
    /// </summary>
    /// <param name="algorithm">HS256 / HS384 / HS512 (case-insensitive)</param>
    /// <param name="secret">Client shared secret (raw; NOT hashed)</param>
    /// <returns>Validation result</returns>
    SymmetricSecretValidationResult ValidateForAlgorithm(string algorithm, string? secret);

    /// <summary>Validate during client create/update for all potential configured HMAC usages.</summary>
    SymmetricSecretValidationResult ValidateClientMutation(Client client);
}

public sealed record SymmetricSecretValidationResult(bool Success, string? Error, int? RequiredBytes = null, int? ActualBytes = null)
{
    public static SymmetricSecretValidationResult Ok() => new(true, null, null, null);
    public static SymmetricSecretValidationResult Fail(string error, int? required = null, int? actual = null) => new(false, error, required, actual);
}
