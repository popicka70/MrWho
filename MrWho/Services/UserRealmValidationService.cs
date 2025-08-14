using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using MrWho.Data;

namespace MrWho.Services;

/// <summary>
/// Implementation of user realm validation service
/// </summary>
public class UserRealmValidationService : IUserRealmValidationService
{
    private readonly ApplicationDbContext _context;
    private readonly UserManager<IdentityUser> _userManager;
    private readonly ILogger<UserRealmValidationService> _logger;

    public UserRealmValidationService(
        ApplicationDbContext context,
        UserManager<IdentityUser> userManager,
        ILogger<UserRealmValidationService> logger)
    {
        _context = context;
        _userManager = userManager;
        _logger = logger;
    }

    public async Task<bool> CanUserAccessClientAsync(IdentityUser user, string clientId)
    {
        var result = await ValidateUserRealmAccessAsync(user, clientId);
        return result.IsValid;
    }

    public async Task<UserRealmValidationResult> ValidateUserRealmAccessAsync(IdentityUser user, string clientId)
    {
        try
        {
            // Get the client and its realm
            var client = await _context.Clients
                .Include(c => c.Realm)
                .FirstOrDefaultAsync(c => c.ClientId == clientId);

            if (client == null)
            {
                _logger.LogWarning("Client {ClientId} not found during realm validation", clientId);
                return new UserRealmValidationResult
                {
                    IsValid = false,
                    Reason = "Client not found",
                    ErrorCode = "CLIENT_NOT_FOUND"
                };
            }

            if (!client.IsEnabled || !client.Realm.IsEnabled)
            {
                _logger.LogWarning("Client {ClientId} or its realm is disabled", clientId);
                return new UserRealmValidationResult
                {
                    IsValid = false,
                    Reason = "Client or realm is disabled",
                    ClientRealm = client.Realm.Name,
                    ErrorCode = "CLIENT_DISABLED"
                };
            }

            // NEW: Enforce assigned users to clients
            var assigned = await _context.ClientUsers.AnyAsync(cu => cu.ClientId == client.Id && cu.UserId == user.Id);
            if (!assigned)
            {
                _logger.LogWarning("User {UserName} is not assigned to client {ClientId}", user.UserName, clientId);
                return new UserRealmValidationResult
                {
                    IsValid = false,
                    Reason = "User not assigned to this client",
                    ClientRealm = client.Realm.Name,
                    ErrorCode = "CLIENT_USER_NOT_ASSIGNED"
                };
            }

            _logger.LogDebug("User {UserName} successfully validated for client {ClientId} in realm '{Realm}'",
                user.UserName, clientId, client.Realm.Name);

            return new UserRealmValidationResult
            {
                IsValid = true,
                ClientRealm = client.Realm.Name
            };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error validating user realm access for user {UserName} and client {ClientId}",
                user.UserName, clientId);
            
            return new UserRealmValidationResult
            {
                IsValid = false,
                Reason = "Internal error during validation",
                ErrorCode = "VALIDATION_ERROR"
            };
        }
    }
}