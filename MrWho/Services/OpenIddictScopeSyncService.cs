using Microsoft.EntityFrameworkCore;
using MrWho.Data;
using MrWho.Models;
using OpenIddict.Abstractions;

namespace MrWho.Services;

/// <summary>
/// Service responsible for synchronizing database scopes with OpenIddict.
/// This service focuses solely on keeping OpenIddict's scope registry in sync with our database.
/// </summary>
public class OpenIddictScopeSyncService : IOpenIddictScopeSyncService
{
    private readonly ApplicationDbContext _context;
    private readonly IOpenIddictScopeManager _scopeManager;
    private readonly ILogger<OpenIddictScopeSyncService> _logger;

    public OpenIddictScopeSyncService(
        ApplicationDbContext context,
        IOpenIddictScopeManager scopeManager,
        ILogger<OpenIddictScopeSyncService> logger)
    {
        _context = context;
        _scopeManager = scopeManager;
        _logger = logger;
    }

    /// <summary>
    /// Synchronizes all enabled scopes from the database with OpenIddict
    /// </summary>
    public async Task SynchronizeAllScopesAsync()
    {
        try
        {
            // Get all enabled scopes from the database
            var enabledScopes = await _context.Scopes
                .Include(s => s.Claims)
                .Where(s => s.IsEnabled)
                .ToListAsync();

            _logger.LogInformation("Synchronizing {ScopeCount} enabled scopes with OpenIddict", enabledScopes.Count);

            foreach (var scope in enabledScopes)
            {
                await RegisterScopeAsync(scope);
            }

            _logger.LogInformation("Successfully synchronized all enabled scopes with OpenIddict");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to synchronize scopes with OpenIddict");
            throw;
        }
    }

    /// <summary>
    /// Registers or updates a single scope with OpenIddict
    /// </summary>
    public async Task RegisterScopeAsync(Scope scope)
    {
        try
        {
            // Check if scope already exists in OpenIddict
            var existingOpenIddictScope = await _scopeManager.FindByNameAsync(scope.Name);

            var descriptor = new OpenIddictScopeDescriptor
            {
                Name = scope.Name,
                DisplayName = scope.DisplayName ?? scope.Name,
                Description = scope.Description
            };

            // Add claims (resources for the scope)
            foreach (var claim in scope.Claims)
            {
                descriptor.Resources.Add(claim.ClaimType);
            }

            if (existingOpenIddictScope != null)
            {
                // Update existing scope
                await _scopeManager.UpdateAsync(existingOpenIddictScope, descriptor);
                _logger.LogDebug("Updated scope '{ScopeName}' in OpenIddict", scope.Name);
            }
            else
            {
                // Create new scope in OpenIddict
                await _scopeManager.CreateAsync(descriptor);
                _logger.LogDebug("Created scope '{ScopeName}' in OpenIddict", scope.Name);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to register scope '{ScopeName}' with OpenIddict", scope.Name);
            throw;
        }
    }

    /// <summary>
    /// Removes a scope from OpenIddict
    /// </summary>
    public async Task RemoveScopeAsync(string scopeName)
    {
        try
        {
            var existingScope = await _scopeManager.FindByNameAsync(scopeName);
            if (existingScope != null)
            {
                await _scopeManager.DeleteAsync(existingScope);
                _logger.LogInformation("Removed scope '{ScopeName}' from OpenIddict", scopeName);
            }
            else
            {
                _logger.LogDebug("Scope '{ScopeName}' not found in OpenIddict, nothing to remove", scopeName);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to remove scope '{ScopeName}' from OpenIddict", scopeName);
            throw;
        }
    }

    /// <summary>
    /// Checks if a scope exists in OpenIddict
    /// </summary>
    public async Task<bool> ScopeExistsAsync(string scopeName)
    {
        try
        {
            var scope = await _scopeManager.FindByNameAsync(scopeName);
            return scope != null;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to check if scope '{ScopeName}' exists in OpenIddict", scopeName);
            return false;
        }
    }
}