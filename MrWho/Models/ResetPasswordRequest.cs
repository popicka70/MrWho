using System.ComponentModel.DataAnnotations;

namespace MrWho.Models;

public class ResetPasswordRequest
{
    [Required]
    [MinLength(6)]
    public string NewPassword { get; set; } = string.Empty;
}
