using System.ComponentModel.DataAnnotations;
using System.Text.Json;

namespace MrWho.Models;

public enum ClientRegistrationStatus
{
    Pending = 0,
    Approved = 1,
    Rejected = 2
}

/// <summary>
/// Represents a pending dynamic client registration awaiting admin approval.
/// Stores the original request JSON plus a few denormalized fields for review.
/// </summary>
public class PendingClientRegistration
{
    [Key]
    public string Id { get; set; } = Guid.NewGuid().ToString();

    [MaxLength(200)]
    public string? SubmittedByUserId { get; set; }

    [MaxLength(256)]
    public string? SubmittedByUserName { get; set; }

    public DateTime SubmittedAt { get; set; } = DateTime.UtcNow;

    public ClientRegistrationStatus Status { get; set; } = ClientRegistrationStatus.Pending;

    public DateTime? ReviewedAt { get; set; }

    [MaxLength(256)]
    public string? ReviewedBy { get; set; }

    [MaxLength(2000)]
    public string? ReviewReason { get; set; }

    // Lightweight denormalized fields for quick listing
    [MaxLength(200)]
    public string? ClientName { get; set; }

    [MaxLength(100)]
    public string? TokenEndpointAuthMethod { get; set; }

    [MaxLength(2000)]
    public string? Scope { get; set; }

    // Comma-separated redirect URIs for quick scan (full set available in RawRequestJson)
    [MaxLength(4000)]
    public string? RedirectUrisCsv { get; set; }

    // Original submitted JSON (RFC7591 subset)
    public string RawRequestJson { get; set; } = string.Empty;

    // Resulting created client references (after approval)
    public string? CreatedClientDbId { get; set; }

    public string? CreatedClientPublicId { get; set; }

    public static PendingClientRegistration FromRequest(DynamicClientRegistrationRequest request, string? userId, string? userName)
    {
        return new PendingClientRegistration
        {
            SubmittedByUserId = userId,
            SubmittedByUserName = userName,
            ClientName = request.ClientName,
            TokenEndpointAuthMethod = request.TokenEndpointAuthMethod,
            Scope = request.Scope,
            RedirectUrisCsv = request.RedirectUris != null ? string.Join(",", request.RedirectUris) : null,
            RawRequestJson = JsonSerializer.Serialize(request)
        };
    }
}
