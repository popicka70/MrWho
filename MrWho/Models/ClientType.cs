namespace MrWho.Models;

/// <summary>
/// Client types
/// </summary>
public enum ClientType
{
    /// <summary>
    /// Confidential client (can store secrets securely)
    /// </summary>
    Confidential = 0,
    
    /// <summary>
    /// Public client (cannot store secrets securely, e.g., SPAs, mobile apps)
    /// </summary>
    Public = 1,
    
    /// <summary>
    /// Machine-to-machine client (service accounts)
    /// </summary>
    Machine = 2
}