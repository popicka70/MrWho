namespace MrWho.Services;

/// <summary>
/// Service for seeding sample realm and client data
/// </summary>
public interface ISeedingService
{
    Task SeedSampleDataAsync(bool recreateData = false);
    Task SeedRealmsAsync();
    Task SeedClientsAsync();
    Task CleanupSampleDataAsync();
}
