using System.ComponentModel.DataAnnotations;

namespace MrWho.Shared.Models;

public class RegisterUserRequest
{
    [Required, EmailAddress]
    public string Email { get; set; } = string.Empty;

    [Required, MinLength(6)]
    public string Password { get; set; } = string.Empty;

    [Required, MinLength(1)]
    public string FirstName { get; set; } = string.Empty;

    [Required, MinLength(1)]
    public string LastName { get; set; } = string.Empty;
}

public class RegisterUserResponse
{
    public bool Success { get; set; }
    public string? UserId { get; set; }
    public string? Error { get; set; }
}
