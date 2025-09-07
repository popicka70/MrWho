using Microsoft.IdentityModel.Tokens;

namespace MrWho.Services;

public interface IKeyManagementService
{
    Task EnsureInitializedAsync(CancellationToken ct = default);

    Task<(IReadOnlyList<SecurityKey> signingKeys, IReadOnlyList<SecurityKey> encryptionKeys)> GetActiveKeysAsync(CancellationToken ct = default);
}
