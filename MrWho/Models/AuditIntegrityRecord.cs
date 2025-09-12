using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace MrWho.Models;

/// <summary>
/// Append-only integrity chained audit record (Phase 1 requirement).
/// Hash chain: RecordHash = SHA256(canonicalJson + PreviousHash + Version).
/// </summary>
public class AuditIntegrityRecord
{
    /// <summary>
    /// ULID string (26 chars Crockford Base32) for sortability.
    /// </summary>
    [Key]
    [StringLength(26)]
    public string Id { get; set; } = UlidGenerator.NewUlid();

    public DateTime TimestampUtc { get; set; } = DateTime.UtcNow;

    [Required, StringLength(100)]
    public string Category { get; set; } = string.Empty;

    [Required, StringLength(150)]
    public string Action { get; set; } = string.Empty;

    [StringLength(50)]
    public string? ActorType { get; set; }

    [StringLength(200)]
    public string? ActorId { get; set; }

    [StringLength(50)]
    public string? SubjectType { get; set; }

    [StringLength(200)]
    public string? SubjectId { get; set; }

    [StringLength(200)]
    public string? RealmId { get; set; }

    [StringLength(100)]
    public string? CorrelationId { get; set; }

    /// <summary>
    /// Arbitrary JSON payload (already serialized, small sized expected)
    /// </summary>
    public string? DataJson { get; set; }

    [StringLength(128)]
    public string? PreviousHash { get; set; }

    [Required, StringLength(128)]
    public string RecordHash { get; set; } = string.Empty;

    /// <summary>
    /// Schema/hash algorithm version (bumped if canonical layout changes)
    /// </summary>
    [Required]
    public int Version { get; set; } = 1;
}

/// <summary>
/// Minimal ULID (Universally Unique Lexicographically Sortable Identifier) generator.
/// Not fully monotonic across threads, but adequate for low contention audit writes.
/// </summary>
internal static class UlidGenerator
{
    private static readonly char[] _encoding = "0123456789ABCDEFGHJKMNPQRSTVWXYZ".ToCharArray();
    private static readonly object _lock = new();
    private static long _lastTimestamp;
    private static byte[] _lastRandom = new byte[10];

    public static string NewUlid()
    {
        Span<char> chars = stackalloc char[26];
        long timestamp;
        Span<byte> randomness = stackalloc byte[10];
        lock (_lock)
        {
            timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            if (timestamp == _lastTimestamp)
            {
                // increment randomness (monotonic within same ms)
                for (int i = 9; i >= 0; i--)
                {
                    if (_lastRandom[i] == 255)
                    {
                        _lastRandom[i] = 0;
                        continue;
                    }
                    _lastRandom[i]++;
                    break;
                }
                _lastRandom.CopyTo(randomness);
            }
            else
            {
                System.Security.Cryptography.RandomNumberGenerator.Fill(randomness);
                randomness.CopyTo(_lastRandom);
                _lastTimestamp = timestamp;
            }
        }
        // Encode timestamp (48 bits => 10 chars) ms since Unix epoch
        // ULID spec: 48-bit timestamp then 80-bit randomness
        for (int i = 9; i >= 0; i--)
        {
            int mod = (int)(timestamp % 32);
            chars[i] = _encoding[mod];
            timestamp /= 32;
        }
        // Encode randomness (80 bits -> 16 chars)
        // Convert 10 bytes to 16 base32 chars
        int charIndex = 10;
        int buffer = 0;
        int bitsLeft = 0;
        for (int i = 0; i < 10; i++)
        {
            buffer = (buffer << 8) | randomness[i];
            bitsLeft += 8;
            while (bitsLeft >= 5)
            {
                bitsLeft -= 5;
                int idx = (buffer >> bitsLeft) & 0x1F;
                chars[charIndex++] = _encoding[idx];
            }
        }
        if (bitsLeft > 0)
        {
            int idx = (buffer << (5 - bitsLeft)) & 0x1F;
            chars[charIndex++] = _encoding[idx];
        }
        return new string(chars);
    }
}
