using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using MrWho.Data;
using MrWho.Models;

namespace MrWho.Services;

/// <summary>
/// Hosted service that runs once on startup to ensure every Identity user has a UserProfile row.
/// Admin user profile is forced Active; others default to New if created here.
/// </summary>
public sealed class UserProfileBackfillHostedService : IHostedService
{
    private readonly IServiceProvider _provider;
    private readonly ILogger<UserProfileBackfillHostedService> _logger;

    public UserProfileBackfillHostedService(IServiceProvider provider, ILogger<UserProfileBackfillHostedService> logger)
    {
        _provider = provider;
        _logger = logger;
    }

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        try
        {
            using var scope = _provider.CreateScope();
            var db = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
            var userManager = scope.ServiceProvider.GetRequiredService<UserManager<IdentityUser>>();

            if (!await db.Database.CanConnectAsync(cancellationToken))
            {
                return;
            }

            var userIdsWithProfile = await db.UserProfiles.AsNoTracking().Select(p => p.UserId).ToListAsync(cancellationToken);
            var allUsers = await userManager.Users.Select(u => new { u.Id, u.UserName, u.Email }).ToListAsync(cancellationToken);

            var missing = allUsers.Where(u => !userIdsWithProfile.Contains(u.Id)).ToList();
            if (missing.Count == 0)
            {
                _logger.LogInformation("UserProfile backfill: no missing profiles.");
                return;
            }

            _logger.LogInformation("UserProfile backfill: creating {Count} missing profiles", missing.Count);
            foreach (var u in missing)
            {
                var isAdmin = string.Equals(u.Email, "admin@mrwho.local", StringComparison.OrdinalIgnoreCase) || string.Equals(u.UserName, "admin@mrwho.local", StringComparison.OrdinalIgnoreCase);
                db.UserProfiles.Add(new UserProfile
                {
                    UserId = u.Id,
                    DisplayName = BuildDisplayName(u.UserName ?? u.Email ?? u.Id),
                    State = isAdmin ? UserState.Active : UserState.New,
                    CreatedAt = DateTime.UtcNow
                });
            }
            await db.SaveChangesAsync(cancellationToken);
            _logger.LogInformation("UserProfile backfill complete.");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "UserProfile backfill failed");
        }
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    private static string BuildDisplayName(string source)
    {
        if (string.IsNullOrWhiteSpace(source))
        {
            return "New User";
        }

        if (source.Contains('@'))
        {
            source = source.Split('@')[0];
        }

        var friendly = source.Replace('.', ' ').Replace('_', ' ').Replace('-', ' ');
        var words = friendly.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        return string.Join(' ', words.Select(w => char.ToUpper(w[0]) + w[1..].ToLower()));
    }
}
