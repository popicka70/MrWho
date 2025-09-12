namespace MrWho.Extensions;

/// <summary>
/// Options controlling database initialization behavior across environments and tests.
/// </summary>
public class DatabaseInitializationOptions
{
    /// <summary>
    /// When true, forces EnsureCreated/EnsureCreatedAsync instead of migrations (primarily for tests).
    /// </summary>
    public bool ForceUseEnsureCreated { get; set; }

    /// <summary>
    /// Skip applying migrations (useful for ephemeral test databases).
    /// </summary>
    public bool SkipMigrations { get; set; }

    /// <summary>
    /// When true, database is dropped/recreated on each initialization (isolated tests).
    /// </summary>
    public bool RecreateDatabase { get; set; }
}
