using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using MrWho.Data;
using MrWho.Models;
using MrWho.Options;

namespace MrWho.Services;

public interface IDeviceAutoLoginService
{
    Task<(string token, DateTime expiresAt)?> IssueTokenAsync(string userId, string deviceId, TimeSpan? lifetime = null, CancellationToken ct = default);
    Task<(IdentityUser? user, string? rotatedToken, DateTime? rotatedExpires)> ValidateAsync(string rawToken, CancellationToken ct = default);
    Task RevokeForDeviceAsync(string userId, string deviceId, CancellationToken ct = default);
}

public sealed class DeviceAutoLoginService : IDeviceAutoLoginService
{
    private readonly ApplicationDbContext _db;
    private readonly UserManager<IdentityUser> _userManager;
    private readonly ILogger<DeviceAutoLoginService> _logger;
    private readonly MrWhoOptions _options;
    private static readonly ConcurrentDictionary<string, (int count, DateTime window)> _attempts = new();

    public DeviceAutoLoginService(ApplicationDbContext db, UserManager<IdentityUser> userManager, ILogger<DeviceAutoLoginService> logger, IOptions<MrWhoOptions> options)
    { _db = db; _userManager = userManager; _logger = logger; _options = options.Value; }

    public async Task<(string token, DateTime expiresAt)?> IssueTokenAsync(string userId, string deviceId, TimeSpan? lifetime = null, CancellationToken ct = default)
    {
        if (!_options.EnableDeviceAutoLogin) return null;
        var device = await _db.UserDevices.FirstOrDefaultAsync(d => d.UserId == userId && d.DeviceId == deviceId && d.IsActive, ct);
        if (device == null) return null;
        var raw = Convert.ToBase64String(RandomNumberGenerator.GetBytes(48));
        var salt = Convert.ToBase64String(RandomNumberGenerator.GetBytes(16));
        var hash = Hash(raw, salt);
        device.DeviceAuthTokenSalt = salt;
        device.DeviceAuthTokenHash = hash;
        var ttlDays = device.IsTrusted ? _options.DeviceAutoLoginTrustedDays : _options.DeviceAutoLoginDefaultDays;
        var expires = DateTime.UtcNow.Add(lifetime ?? TimeSpan.FromDays(ttlDays));
        device.DeviceAuthTokenExpiresAt = expires;
        device.UpdatedAt = DateTime.UtcNow;
        await _db.SaveChangesAsync(ct);
        _logger.LogInformation("Issued device auto-login token for device {DeviceId} user {UserId} exp {Exp}", deviceId, userId, expires);
        return (raw, expires);
    }

    public async Task<(IdentityUser? user, string? rotatedToken, DateTime? rotatedExpires)> ValidateAsync(string rawToken, CancellationToken ct = default)
    {
        if (!_options.EnableDeviceAutoLogin) return (null, null, null);
        if (string.IsNullOrWhiteSpace(rawToken)) return (null, null, null);

        // Basic attempt throttle keyed by token length bucket to avoid memory explosion
        var key = $"len:{rawToken.Length}";
        var now = DateTime.UtcNow;
        var entry = _attempts.GetOrAdd(key, _ => (0, now));
        if (entry.window.AddMinutes(1) < now) entry = (0, now);
        if (entry.count >= _options.DeviceAutoLoginMaxAttemptsPerMinute) return (null, null, null);
        _attempts[key] = (entry.count + 1, entry.window);

        var candidates = await _db.UserDevices.Where(d => d.DeviceAuthTokenHash != null && d.DeviceAuthTokenExpiresAt > now && d.IsActive).OrderBy(d=>d.DeviceAuthTokenExpiresAt).ToListAsync(ct);
        foreach (var d in candidates)
        {
            try
            {
                if (d.DeviceAuthTokenSalt == null || d.DeviceAuthTokenHash == null) continue;
                if (SecureEquals(Hash(rawToken, d.DeviceAuthTokenSalt), d.DeviceAuthTokenHash))
                {
                    var user = await _userManager.FindByIdAsync(d.UserId);
                    if (user == null) return (null, null, null);
                    d.LastUsedAt = now;
                    string? rotated = null; DateTime? rotatedExp = null;
                    if (_options.DeviceAutoLoginRotateOnUse)
                    {
                        rotated = Convert.ToBase64String(RandomNumberGenerator.GetBytes(48));
                        var newSalt = Convert.ToBase64String(RandomNumberGenerator.GetBytes(16));
                        d.DeviceAuthTokenSalt = newSalt;
                        d.DeviceAuthTokenHash = Hash(rotated, newSalt);
                        rotatedExp = d.DeviceAuthTokenExpiresAt; // unchanged
                    }
                    await _db.SaveChangesAsync(ct);
                    return (user, rotated, rotatedExp);
                }
            }
            catch { }
        }
        return (null, null, null);
    }

    public async Task RevokeForDeviceAsync(string userId, string deviceId, CancellationToken ct = default)
    {
        var device = await _db.UserDevices.FirstOrDefaultAsync(d => d.UserId == userId && d.DeviceId == deviceId, ct);
        if (device == null) return;
        device.DeviceAuthTokenHash = null;
        device.DeviceAuthTokenSalt = null;
        device.DeviceAuthTokenExpiresAt = null;
        device.UpdatedAt = DateTime.UtcNow;
        await _db.SaveChangesAsync(ct);
        _logger.LogInformation("Revoked device auto-login token for device {DeviceId} user {UserId}", deviceId, userId);
    }

    private static string Hash(string raw, string salt)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(raw + ":" + salt));
        return Convert.ToBase64String(bytes);
    }

    private static bool SecureEquals(string a, string b)
    {
        if (a.Length != b.Length) return false;
        var diff = 0; for (int i = 0; i < a.Length; i++) diff |= a[i] ^ b[i];
        return diff == 0;
    }
}
