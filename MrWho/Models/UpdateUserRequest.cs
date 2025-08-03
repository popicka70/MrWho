using System.ComponentModel.DataAnnotations;

namespace MrWho.Models;

public class UpdateUserRequest
{
    [EmailAddress]
    public string? Email { get; set; }

    public string? UserName { get; set; }
    public string? PhoneNumber { get; set; }
    public bool? EmailConfirmed { get; set; }
    public bool? PhoneNumberConfirmed { get; set; }
    public bool? TwoFactorEnabled { get; set; }
}
