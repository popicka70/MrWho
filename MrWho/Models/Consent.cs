using System.ComponentModel.DataAnnotations;

namespace MrWho.Models;

public class Consent
{
    [Key]
    public Guid Id { get; set; }

    [Required]
    public string UserId { get; set; } = null!;

    [Required]
    public string ClientId { get; set; } = null!;

    // JSON array of granted scopes (e.g., ["openid","profile"]) stored as string
    [Required]
    public string GrantedScopesJson { get; set; } = "[]";

    public DateTime CreatedAt { get; set; }
    public DateTime UpdatedAt { get; set; }

    // For future schema evolution / concurrency
    public int Version { get; set; } = 1;

    public IReadOnlyCollection<string> GetGrantedScopes()
        => System.Text.Json.JsonSerializer.Deserialize<string[]>(GrantedScopesJson) ?? Array.Empty<string>();

    public void SetGrantedScopes(IEnumerable<string> scopes)
        => GrantedScopesJson = System.Text.Json.JsonSerializer.Serialize(scopes.Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(s => s));
}
