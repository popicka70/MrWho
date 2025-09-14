namespace MrWho.Shared.Extensions;

/// <summary>
/// Extension methods for working with shared models
/// </summary>
public static class SharedModelExtensions
{
    /// <summary>
    /// Creates a paged result with calculated total pages
    /// </summary>
    public static Models.PagedResult<T> ToPagedResult<T>(this IEnumerable<T> items, int totalCount, int page, int pageSize)
    {
        return new Models.PagedResult<T>
        {
            Items = items.ToList(),
            TotalCount = totalCount,
            Page = page,
            PageSize = pageSize,
            TotalPages = (int)Math.Ceiling(totalCount / (double)pageSize)
        };
    }

    /// <summary>
    /// Validates that a client uses standard scopes
    /// </summary>
    public static bool UsesStandardScopes(this Models.ClientDto client)
    {
        var standardScopes = new[]
        {
            StandardScopes.OpenId,
            StandardScopes.Email,
            StandardScopes.Profile,
            StandardScopes.Roles,
            StandardScopes.ApiRead,
            StandardScopes.ApiWrite
        };

        return client.Scopes.All(scope => standardScopes.Contains(scope));
    }

    /// <summary>
    /// Gets default scopes for admin clients
    /// </summary>
    public static string[] GetAdminClientScopes()
    {
        return MrWhoConstants.AdminClientDefaults.Scopes;
    }
}