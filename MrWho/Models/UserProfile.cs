using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Identity;

namespace MrWho.Models;

/// <summary>
/// Optional profile data for Identity users
/// </summary>
public class UserProfile
{
    [Key]
    public string UserId { get; set; } = string.Empty; // PK + FK to AspNetUsers(Id)

    [MaxLength(256)]
    public string? FirstName { get; set; }

    [MaxLength(256)]
    public string? LastName { get; set; }

    [MaxLength(512)]
    public string? DisplayName { get; set; }

    public UserState State { get; set; } = UserState.New;

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime? UpdatedAt { get; set; }
}
