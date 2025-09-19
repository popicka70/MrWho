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

    /// <summary>
    /// Metrics read policy: allows access for callers with role "metrics.read" OR scope "mrwho.metrics".
    /// Works for both user tokens (role) and M2M/bearer tokens (scope).
    /// </summary>
    public const string MetricsRead = "MetricsRead";
}
