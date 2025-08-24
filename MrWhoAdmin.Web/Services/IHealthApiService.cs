namespace MrWhoAdmin.Web.Services;

/// <summary>
/// Service interface for health check API operations
/// </summary>
public interface IHealthApiService
{
    /// <summary>
    /// Gets basic health status
    /// </summary>
    /// <returns>Basic health status information</returns>
    Task<HealthStatus?> GetBasicHealthAsync();

    /// <summary>
    /// Gets detailed health status with comprehensive checks
    /// </summary>
    /// <returns>Detailed health status information</returns>
    Task<DetailedHealthStatus?> GetDetailedHealthAsync();

    /// <summary>
    /// Gets liveness check status
    /// </summary>
    /// <returns>Liveness status information</returns>
    Task<LivenessStatus?> GetLivenessAsync();

    /// <summary>
    /// Gets readiness check status
    /// </summary>
    /// <returns>Readiness status information</returns>
    Task<ReadinessStatus?> GetReadinessAsync();

    /// <summary>
    /// Gets authentication schemes information
    /// </summary>
    /// <returns>Authentication schemes information</returns>
    Task<AuthSchemesInfo?> GetAuthSchemesAsync();
}

/// <summary>
/// Basic health status model
/// </summary>
public class HealthStatus
{
    public string Status { get; set; } = string.Empty;
    public DateTime Timestamp { get; set; }
    public string Version { get; set; } = string.Empty;
    public string Application { get; set; } = string.Empty;
}

/// <summary>
/// Detailed health status model
/// </summary>
public class DetailedHealthStatus : HealthStatus
{
    public Dictionary<string, object> Checks { get; set; } = new();
    public EnvironmentInfo Environment { get; set; } = new();
}

/// <summary>
/// Environment information model
/// </summary>
public class EnvironmentInfo
{
    public string MachineName { get; set; } = string.Empty;
    public string OsVersion { get; set; } = string.Empty;
    public int ProcessorCount { get; set; }
    public long WorkingSet { get; set; }
    public long ManagedMemory { get; set; }
}

/// <summary>
/// Liveness status model
/// </summary>
public class LivenessStatus
{
    public string Status { get; set; } = string.Empty;
    public DateTime Timestamp { get; set; }
}

/// <summary>
/// Readiness status model
/// </summary>
public class ReadinessStatus
{
    public string Status { get; set; } = string.Empty;
    public DateTime Timestamp { get; set; }
    public string? Error { get; set; }
}

/// <summary>
/// Authentication schemes information model
/// </summary>
public class AuthSchemesInfo
{
    public DateTime Timestamp { get; set; }
    public string Application { get; set; } = string.Empty;
    public UserInfo User { get; set; } = new();
    public List<CookieInfo> Cookies { get; set; } = new();
    public SchemeInfo Schemes { get; set; } = new();
}

/// <summary>
/// User information model
/// </summary>
public class UserInfo
{
    public bool IsAuthenticated { get; set; }
    public string? Name { get; set; }
    public string? AuthenticationType { get; set; }
    public int ClaimsCount { get; set; }
}

/// <summary>
/// Cookie information model
/// </summary>
public class CookieInfo
{
    public string Name { get; set; } = string.Empty;
    public int Length { get; set; }
}

/// <summary>
/// Authentication schemes information model
/// </summary>
public class SchemeInfo
{
    public string DefaultScheme { get; set; } = string.Empty;
    public string ChallengeScheme { get; set; } = string.Empty;
    public string Note { get; set; } = string.Empty;
}