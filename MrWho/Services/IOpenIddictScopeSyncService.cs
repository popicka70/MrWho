using MrWho.Models;

namespace MrWho.Services;

/// <summary>
/// Service responsible for synchronizing database scopes with OpenIddict.
/// This service focuses solely on keeping OpenIddict's scope registry in sync with our database.
/// </summary>
public interface IOpenIddictScopeSyncService
{
    /// <summary>
    /// Synchronizes all enabled scopes from the database with OpenIddict
    /// </summary>
    Task SynchronizeAllScopesAsync();

    /// <summary>
    /// Registers or updates a single scope with OpenIddict
    /// </summary>
    Task RegisterScopeAsync(Scope scope);

    /// <summary>
    /// Removes a scope from OpenIddict
    /// </summary>
    Task RemoveScopeAsync(string scopeName);

    /// <summary>
    /// Checks if a scope exists in OpenIddict
    /// </summary>
    Task<bool> ScopeExistsAsync(string scopeName);
}
