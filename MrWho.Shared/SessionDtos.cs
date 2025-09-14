namespace MrWho.Shared;

/// <summary>
/// Represents an active user session
/// </summary>
public class ActiveSessionDto
{
    public string Id { get; set; } = string.Empty;
    public string UserId { get; set; } = string.Empty;
    public string UserName { get; set; } = string.Empty;
    public string UserEmail { get; set; } = string.Empty;
    public string ClientId { get; set; } = string.Empty;
    public string ClientName { get; set; } = string.Empty;
    public string Subject { get; set; } = string.Empty;
    public List<string> Scopes { get; set; } = new();
    public DateTime CreatedAt { get; set; }
    public DateTime? LastActivity { get; set; }
    public DateTime? ExpiresAt { get; set; }
    public string Status { get; set; } = string.Empty;
    public bool HasRefreshToken { get; set; }
    public int TokenCount { get; set; }
    public string IpAddress { get; set; } = string.Empty;
    public string UserAgent { get; set; } = string.Empty;
    public string SessionType { get; set; } = string.Empty; // "Web", "API", "Mobile", etc.
}

/// <summary>
/// Session statistics and summary information
/// </summary>
public class SessionStatisticsDto
{
    public int TotalActiveSessions { get; set; }
    public int UniqueActiveUsers { get; set; }
    public int ActiveClients { get; set; }
    public Dictionary<string, int> SessionsByClient { get; set; } = new();
    public Dictionary<string, int> SessionsByType { get; set; } = new();
    public DateTime OldestSession { get; set; }
    public DateTime? MostRecentSession { get; set; }
    public int ExpiringSoon { get; set; } // Sessions expiring in next hour
    public int SessionsToday { get; set; }
    public int SessionsThisWeek { get; set; }
}
