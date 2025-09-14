using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using MrWho.Data;
using MrWho.Models;

namespace MrWho.Services;

public sealed class ClientRoleService : IClientRoleService
{
    private readonly ApplicationDbContext _db;
    private readonly UserManager<IdentityUser> _userManager;
    private readonly IMemoryCache _cache;
    private readonly ILogger<ClientRoleService> _logger;

    private static readonly MemoryCacheEntryOptions CacheOptions = new()
    {
        AbsoluteExpirationRelativeToNow = TimeSpan.FromMinutes(5)
    };

    public ClientRoleService(ApplicationDbContext db, UserManager<IdentityUser> userManager, IMemoryCache cache, ILogger<ClientRoleService> logger)
    {
        _db = db;
        _userManager = userManager;
        _cache = cache;
        _logger = logger;
    }

    public async Task<IReadOnlyList<string>> GetClientRolesAsync(string userId, string clientId, CancellationToken ct = default)
    {
        var key = ($"clientroles:{userId}:{clientId}");
        if (_cache.TryGetValue(key, out IReadOnlyList<string>? cached) && cached != null) {
            return cached;
        }

        var roles = await _db.UserClientRoles
            .Where(ucr => ucr.UserId == userId && ucr.ClientRole.ClientId == clientId)
            .Select(ucr => ucr.ClientRole.Name)
            .Distinct()
            .OrderBy(n => n)
            .ToListAsync(ct);

        _cache.Set(key, roles, CacheOptions);
        return roles;
    }

    public async Task<IReadOnlyList<string>> GetEffectiveRolesAsync(string userId, string clientId, RoleInclusion inclusion, CancellationToken ct = default)
    {
        List<string> result = new();

        if (inclusion is RoleInclusion.GlobalOnly or RoleInclusion.GlobalAndClient)
        {
            var user = await _userManager.FindByIdAsync(userId);
            if (user != null)
            {
                var globalRoles = await _userManager.GetRolesAsync(user);
                result.AddRange(globalRoles);
            }
        }

        if (inclusion is RoleInclusion.ClientOnly or RoleInclusion.GlobalAndClient)
        {
            var clientRoles = await GetClientRolesAsync(userId, clientId, ct);
            result.AddRange(clientRoles.Select(r => r));
        }

        return result.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
    }

    public async Task AddRoleToUserAsync(string userId, string clientId, string roleName, CancellationToken ct = default)
    {
        var normalized = roleName.Trim().ToUpperInvariant();
        var role = await _db.ClientRoles.FirstOrDefaultAsync(r => r.ClientId == clientId && r.NormalizedName == normalized, ct);
        if (role == null)
        {
            role = new ClientRole { ClientId = clientId, Name = roleName.Trim(), NormalizedName = normalized };
            _db.ClientRoles.Add(role);
            await _db.SaveChangesAsync(ct);
        }

        var exists = await _db.UserClientRoles.AnyAsync(u => u.UserId == userId && u.ClientRoleId == role.Id, ct);
        if (!exists)
        {
            _db.UserClientRoles.Add(new UserClientRole { UserId = userId, ClientRoleId = role.Id });
            await _db.SaveChangesAsync(ct);
            Invalidate(userId, clientId);
        }
    }

    public async Task RemoveRoleFromUserAsync(string userId, string clientId, string roleName, CancellationToken ct = default)
    {
        var normalized = roleName.Trim().ToUpperInvariant();
        var role = await _db.ClientRoles.FirstOrDefaultAsync(r => r.ClientId == clientId && r.NormalizedName == normalized, ct);
        if (role == null) {
            return;
        }

        var link = await _db.UserClientRoles.FirstOrDefaultAsync(u => u.UserId == userId && u.ClientRoleId == role.Id, ct);
        if (link != null)
        {
            _db.UserClientRoles.Remove(link);
            await _db.SaveChangesAsync(ct);
            Invalidate(userId, clientId);
        }
    }

    private void Invalidate(string userId, string clientId)
    {
        _cache.Remove($"clientroles:{userId}:{clientId}");
        _logger.LogDebug("Invalidated client role cache for user {UserId} client {ClientId}", userId, clientId);
    }
}
