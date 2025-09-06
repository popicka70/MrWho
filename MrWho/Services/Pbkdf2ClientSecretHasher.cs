using System.Security.Cryptography;
using System.Text;

namespace MrWho.Services;

/// <summary>
/// PBKDF2-SHA256 secret hasher with format: PBKDF2$iter$salt$b64hash
/// </summary>
public sealed class Pbkdf2ClientSecretHasher : IClientSecretHasher
{
    private const int DefaultIterations = 200_000; // modern default
    private const int SaltSize = 16;
    private const int KeySize = 32; // 256-bit

    public string HashSecret(string secret)
    {
        var salt = RandomNumberGenerator.GetBytes(SaltSize);
        var dk = Rfc2898DeriveBytes.Pbkdf2(Encoding.UTF8.GetBytes(secret), salt, DefaultIterations, HashAlgorithmName.SHA256, KeySize);
        var result = $"PBKDF2$sha256${DefaultIterations}${Convert.ToBase64String(salt)}${Convert.ToBase64String(dk)}";
        return result;
    }

    public bool Verify(string secret, string storedHash)
    {
        try
        {
            // Format: PBKDF2$sha256$iter$salt$hash
            var parts = storedHash.Split('$');
            if (parts.Length != 5) return false;
            if (!string.Equals(parts[0], "PBKDF2", StringComparison.OrdinalIgnoreCase)) return false;
            var algo = parts[1];
            if (!int.TryParse(parts[2], out var iter)) return false;
            var salt = Convert.FromBase64String(parts[3]);
            var hash = Convert.FromBase64String(parts[4]);

            var dk = algo.Equals("sha256", StringComparison.OrdinalIgnoreCase)
                ? Rfc2898DeriveBytes.Pbkdf2(secret, salt, iter, HashAlgorithmName.SHA256, hash.Length)
                : Rfc2898DeriveBytes.Pbkdf2(secret, salt, iter, HashAlgorithmName.SHA512, hash.Length);

            return CryptographicOperations.FixedTimeEquals(dk, hash);
        }
        catch
        {
            return false;
        }
    }
}
