using System.Text.Json.Serialization;

namespace MrWho.Shared;

/// <summary>
/// Client types for OpenIdConnect clients
/// </summary>
[JsonConverter(typeof(JsonStringEnumConverter))]
public enum ClientType
{
    /// <summary>
    /// Confidential client - can securely store credentials
    /// </summary>
    Confidential = 0,

    /// <summary>
    /// Public client - cannot securely store credentials
    /// </summary>
    Public = 1,

    /// <summary>
    /// Machine-to-machine client
    /// </summary>
    Machine = 2
}
