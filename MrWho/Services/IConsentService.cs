using MrWho.Models;

namespace MrWho.Services;

public interface IConsentService
{
    Task<Consent?> GetAsync(string userId, string clientId, CancellationToken ct = default);
    Task<Consent> GrantAsync(string userId, string clientId, IEnumerable<string> grantedScopes, CancellationToken ct = default);
    Task ForgetAsync(string userId, string clientId, CancellationToken ct = default);

    /// <summary>
    /// Returns the missing scopes that require fresh consent. If none missing, returns empty.
    /// </summary>
    IReadOnlyList<string> DiffMissingScopes(IEnumerable<string> requested, IEnumerable<string> alreadyGranted);
}
