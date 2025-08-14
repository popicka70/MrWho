namespace MrWho.Shared.Models;

/// <summary>
/// DTO for returning a user's profile state
/// </summary>
public class UserProfileStateDto
{
    public string State { get; set; } = "New"; // New | Active | Suspended | Disabled
}

/// <summary>
/// Request to change a user's profile state
/// </summary>
public class SetUserProfileStateRequest
{
    public string State { get; set; } = string.Empty;
}
