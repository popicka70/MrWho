namespace MrWho.Shared;

/// <summary>
/// Centralized authorization policy names used across the solution.
/// Use these constants instead of string literals to avoid typos and ease refactors.
/// </summary>
public static class AuthorizationPolicies
{
    /// <summary>
    /// Requires callers to be authenticated as the Admin client/API.
    /// </summary>
    public const string AdminClientApi = "AdminClientApi";
}
