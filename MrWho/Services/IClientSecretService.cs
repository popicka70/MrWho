using MrWho.Models;

namespace MrWho.Services;

public interface IClientSecretService
{
    Task<(ClientSecretHistory record, string? plainSecret)> SetNewSecretAsync(string clientId, string? providedPlaintext = null, DateTime? expiresAt = null, bool markOldAsRetired = true, CancellationToken ct = default);
    Task<bool> VerifyAsync(string clientPublicIdOrDbId, string presentedSecret, CancellationToken ct = default);
    /// <summary>
    /// Returns the active plaintext secret for the given client (decrypting from history) or null if none.
    /// Only returns a secret for active, non-expired secret history entry.
    /// </summary>
    Task<string?> GetActivePlaintextAsync(string clientPublicIdOrDbId, CancellationToken ct = default);
}
