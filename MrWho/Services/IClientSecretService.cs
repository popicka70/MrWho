using MrWho.Models;

namespace MrWho.Services;

public interface IClientSecretService
{
    Task<(ClientSecretHistory record, string? plainSecret)> SetNewSecretAsync(string clientId, string? providedPlaintext = null, DateTime? expiresAt = null, bool markOldAsRetired = true, CancellationToken ct = default);
    Task<bool> VerifyAsync(string clientPublicIdOrDbId, string presentedSecret, CancellationToken ct = default);
}
