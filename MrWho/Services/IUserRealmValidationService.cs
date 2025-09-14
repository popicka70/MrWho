using Microsoft.AspNetCore.Identity;

namespace MrWho.Services;

/// <summary>
/// Service for validating if a user can access a specific client based on realm restrictions
/// </summary>
public interface IUserRealmValidationService
{
    /// <summary>
    /// Validates if a user can authenticate to a specific client
    /// </summary>
    /// <param name="user">The user attempting to authenticate</param>
    /// <param name="clientId">The client ID the user is trying to access</param>
    /// <returns>True if the user can access the client, false otherwise</returns>
    Task<bool> CanUserAccessClientAsync(IdentityUser user, string clientId);

    /// <summary>
    /// Gets the realm restriction information for a user and client
    /// </summary>
    /// <param name="user">The user attempting to authenticate</param>
    /// <param name="clientId">The client ID the user is trying to access</param>
    /// <returns>Validation result with details</returns>
    Task<UserRealmValidationResult> ValidateUserRealmAccessAsync(IdentityUser user, string clientId);
}

/// <summary>
/// Result of user realm validation
/// </summary>
public class UserRealmValidationResult
{
    public bool IsValid { get; set; }
    public string? Reason { get; set; }
    public string? ClientRealm { get; set; }
    public string? ErrorCode { get; set; }
}