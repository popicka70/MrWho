using System.Collections.Generic;

namespace MrWho.Shared.Models;

/// <summary>
/// Aggregated data required to render the Edit User page in a single roundtrip.
/// </summary>
public class UserEditContextDto
{
    public UserWithClaimsDto? User { get; set; }
    public List<RoleDto> UserRoles { get; set; } = new();
    public List<RoleDto> AvailableRoles { get; set; } = new();
    public List<UserClientDto> AssignedClients { get; set; } = new();
    public List<ClientDto> AvailableClients { get; set; } = new();
    public UserProfileStateDto? ProfileState { get; set; }

    // New: complete client list (assigned + unassigned) as seen by admin (subset limited server side)
    public List<ClientDto> AllClients { get; set; } = new();

    // New: all defined client-scoped roles across clients
    public List<ClientRoleDto> AllClientRoles { get; set; } = new();

    // New: user client role assignments grouped by client (ClientId -> role names)
    public Dictionary<string, List<string>> UserClientRolesByClient { get; set; } = new();
}
