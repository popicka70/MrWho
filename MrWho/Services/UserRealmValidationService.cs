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

            // Determine user's realm based on business rules
            var userRealm = await DetermineUserRealmAsync(user);
            
            _logger.LogDebug("User {UserName} belongs to realm '{UserRealm}', client {ClientId} belongs to realm '{ClientRealm}'",
                user.UserName, userRealm, clientId, client.Realm.Name);

            // Check if user's realm matches client's realm
            if (userRealm != client.Realm.Name)
            {
                _logger.LogWarning("User {UserName} from realm '{UserRealm}' attempted to access client {ClientId} from realm '{ClientRealm}'",
                    user.UserName, userRealm, clientId, client.Realm.Name);
                
                return new UserRealmValidationResult
                {
                    IsValid = false,
                    Reason = $"User belongs to realm '{userRealm}' but client belongs to realm '{client.Realm.Name}'",
                    UserRealm = userRealm,
                    ClientRealm = client.Realm.Name,
                    ErrorCode = "REALM_MISMATCH"
                };
            }

            _logger.LogDebug("User {UserName} successfully validated for client {ClientId} in realm '{Realm}'",
                user.UserName, clientId, client.Realm.Name);

            return new UserRealmValidationResult
            {
                IsValid = true,
                UserRealm = userRealm,
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

    /// <summary>
    /// Determines which realm a user belongs to based on business rules
    /// </summary>
    private async Task<string> DetermineUserRealmAsync(IdentityUser user)
    {
        try
        {
            // Method 1: Check for explicit realm claim
            var claims = await _userManager.GetClaimsAsync(user);
            var realmClaim = claims.FirstOrDefault(c => c.Type == "realm");
            if (!string.IsNullOrEmpty(realmClaim?.Value))
            {
                _logger.LogDebug("User {UserName} has explicit realm claim: {Realm}", user.UserName, realmClaim.Value);
                return realmClaim.Value;
            }

            // Method 2: Determine realm based on username patterns
            var realm = DetermineRealmFromUsername(user.UserName!);
            _logger.LogDebug("User {UserName} assigned to realm '{Realm}' based on username pattern", user.UserName, realm);
            return realm;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error determining realm for user {UserName}", user.UserName);
            return "default"; // Fallback to default realm
        }
    }

    /// <summary>
    /// Determines realm based on username patterns
    /// </summary>
    private string DetermineRealmFromUsername(string username)
    {
        // Business rules for realm assignment based on username:
        
        // 1. Admin users (admin@mrwho.local) belong to admin realm
        if (username.Equals("admin@mrwho.local", StringComparison.OrdinalIgnoreCase) ||
            username.StartsWith("admin", StringComparison.OrdinalIgnoreCase))
        {
            return "admin";
        }

        // 2. Demo users (demo1@example.com, demo*@example.com) belong to demo realm
        if (username.Contains("@example.com", StringComparison.OrdinalIgnoreCase) ||
            username.StartsWith("demo", StringComparison.OrdinalIgnoreCase))
        {
            return "demo";
        }

        // 3. Test users belong to default realm
        if (username.Contains("test", StringComparison.OrdinalIgnoreCase) ||
            username.Contains("postman", StringComparison.OrdinalIgnoreCase))
        {
            return "default";
        }

        // 4. Default fallback
        return "default";
    }
}