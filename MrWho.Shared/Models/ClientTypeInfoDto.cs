using MrWho.Shared;

namespace MrWho.Shared.Models;

/// <summary>
/// DTO containing detailed information about a client type
/// </summary>
public class ClientTypeInfoDto
{
    /// <summary>
    /// The client type enum value
    /// </summary>
    public ClientType Type { get; set; }

    /// <summary>
    /// Display name of the client type
    /// </summary>
    public string Name { get; set; } = string.Empty;

    /// <summary>
    /// Detailed description of the client type
    /// </summary>
    public string Description { get; set; } = string.Empty;

    /// <summary>
    /// Key characteristics of this client type
    /// </summary>
    public List<string> Characteristics { get; set; } = new();

    /// <summary>
    /// Recommended OAuth2/OIDC flows for this client type
    /// </summary>
    public List<string> RecommendedFlows { get; set; } = new();

    /// <summary>
    /// Security considerations specific to this client type
    /// </summary>
    public List<string> SecurityConsiderations { get; set; } = new();

    /// <summary>
    /// Common use cases for this client type
    /// </summary>
    public List<string> UseCases { get; set; } = new();
}