using System.Security.Cryptography;
using System.Text;

namespace MrWho.Services;

/// <summary>
/// SHA-256 implementation of IIntegrityHashService. Encapsulates hashing to allow future upgrades (e.g. BLAKE3) while keeping versioned logic.
/// </summary>
public sealed class IntegrityHashService : IIntegrityHashService
{
    public string ComputeChainHash(string canonical, string? previousHash, int version)
    {
        // Defensive checks
        canonical ??= string.Empty;
        previousHash ??= string.Empty;
        var material = canonical + previousHash + version.ToString();
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(material)));
    }
}
