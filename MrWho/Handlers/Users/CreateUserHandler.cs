using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore; // added for EF operations
using MrWho.Data; // added
using MrWho.Models;
using MrWho.Shared.Models;

namespace MrWho.Handlers.Users;

public class CreateUserHandler : ICreateUserHandler
{
    private readonly UserManager<IdentityUser> _userManager;
    private readonly ApplicationDbContext _db; // added
    private readonly ILogger<CreateUserHandler> _logger;

    public CreateUserHandler(UserManager<IdentityUser> userManager, ApplicationDbContext db, ILogger<CreateUserHandler> logger) // updated ctor
    {
        _userManager = userManager;
        _db = db;
        _logger = logger;
    }

    public async Task<(bool Success, UserDto? User, IEnumerable<string> Errors)> HandleAsync(CreateUserRequest request)
    {
        try
        {
            var resolvedUserName = request.UserName ?? request.Email ?? Guid.NewGuid().ToString("n");
            var resolvedEmail = request.Email ?? request.UserName ?? ($"{Guid.NewGuid():n}@local.invalid");
            var user = new IdentityUser
            {
                UserName = resolvedUserName,
                Email = resolvedEmail,
                PhoneNumber = request.PhoneNumber,
                EmailConfirmed = request.EmailConfirmed,
                PhoneNumberConfirmed = request.PhoneNumberConfirmed,
                TwoFactorEnabled = request.TwoFactorEnabled
            };

            var result = await _userManager.CreateAsync(user, request.Password);

            if (result.Succeeded)
            {
                // Create associated UserProfile immediately (option 1 implementation)
                try
                {
                    var existingProfile = await _db.UserProfiles.FirstOrDefaultAsync(p => p.UserId == user.Id);
                    if (existingProfile == null)
                    {
                        var isAdmin = string.Equals(user.Email, "admin@mrwho.local", StringComparison.OrdinalIgnoreCase) || string.Equals(user.UserName, "admin@mrwho.local", StringComparison.OrdinalIgnoreCase);
                        _db.UserProfiles.Add(new UserProfile
                        {
                            UserId = user.Id,
                            DisplayName = BuildDisplayName(user.UserName ?? user.Email ?? user.Id),
                            State = isAdmin ? UserState.Active : UserState.New,
                            CreatedAt = DateTime.UtcNow
                        });
                        await _db.SaveChangesAsync();
                    }
                }
                catch (Exception ex)
                {
                    // Non-fatal; log but still return success for user creation
                    _logger.LogError(ex, "Failed creating UserProfile for user {UserId}", user.Id);
                }

                _logger.LogInformation("Successfully created user {UserName} with ID {UserId}", user.UserName, user.Id);

                var userDto = new UserDto
                {
                    Id = user.Id,
                    UserName = user.UserName ?? string.Empty,
                    Email = user.Email ?? string.Empty,
                    EmailConfirmed = user.EmailConfirmed,
                    PhoneNumber = user.PhoneNumber,
                    PhoneNumberConfirmed = user.PhoneNumberConfirmed,
                    TwoFactorEnabled = user.TwoFactorEnabled,
                    LockoutEnabled = user.LockoutEnabled,
                    LockoutEnd = user.LockoutEnd,
                    AccessFailedCount = user.AccessFailedCount
                };

                return (true, userDto, Enumerable.Empty<string>());
            }

            var errors = result.Errors.Select(e => e.Description);
            _logger.LogWarning("Failed to create user {UserName}: {Errors}", request.UserName, string.Join(", ", errors));
            return (false, null, errors);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error creating user {UserName}", request.UserName);
            return (false, null, new[] { "An unexpected error occurred while creating the user." });
        }
    }

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
