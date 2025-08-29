namespace MrWho.Services;

/// <summary>
/// Service for seeding realm, client, identity, and sample data.
/// Consolidated single entry point: SeedAsync() for core required data.
/// </summary>
public interface ISeedingService
{
    /// <summary>
    /// Seeds all essential data (realms, clients, roles, users, scopes, api resources, identity resources, claim types, identity providers).
    /// Idempotent - safe to call multiple times but should be invoked once at startup.
    /// </summary>
    Task SeedAsync();

    Task SeedSampleDataAsync(bool recreateData = false);
    Task SeedRealmsAsync();
    Task SeedClientsAsync();
    Task CleanupSampleDataAsync();
}
