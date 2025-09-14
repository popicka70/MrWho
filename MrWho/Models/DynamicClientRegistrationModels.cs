using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;
using MrWho.Shared;

namespace MrWho.Models;

/// <summary>
/// Incoming dynamic client registration request (RFC 7591 subset)
/// </summary>
public class DynamicClientRegistrationRequest
{
    [JsonPropertyName("client_name")] public string? ClientName { get; set; }
    [JsonPropertyName("redirect_uris")] public List<string>? RedirectUris { get; set; }
    [JsonPropertyName("post_logout_redirect_uris")] public List<string>? PostLogoutRedirectUris { get; set; }
    [JsonPropertyName("grant_types")] public List<string>? GrantTypes { get; set; }
    [JsonPropertyName("response_types")] public List<string>? ResponseTypes { get; set; }
    [JsonPropertyName("scope")] public string? Scope { get; set; }
    [JsonPropertyName("token_endpoint_auth_method")] public string? TokenEndpointAuthMethod { get; set; }
    [JsonPropertyName("application_type")] public string? ApplicationType { get; set; }
    [JsonPropertyName("client_uri")] public string? ClientUri { get; set; }
    [JsonPropertyName("logo_uri")] public string? LogoUri { get; set; }
}

/// <summary>
/// Response to successful dynamic client registration
/// </summary>
public class DynamicClientRegistrationResponse
{
    [JsonPropertyName("client_id")] public string ClientId { get; set; } = string.Empty;
    [JsonPropertyName("client_secret"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] public string? ClientSecret { get; set; }
    [JsonPropertyName("client_id_issued_at")] public long ClientIdIssuedAt { get; set; }
    [JsonPropertyName("client_secret_expires_at")] public long ClientSecretExpiresAt { get; set; } = 0; // never expires for now
    [JsonPropertyName("redirect_uris"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] public IEnumerable<string>? RedirectUris { get; set; }
    [JsonPropertyName("post_logout_redirect_uris"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] public IEnumerable<string>? PostLogoutRedirectUris { get; set; }
    [JsonPropertyName("grant_types"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] public IEnumerable<string>? GrantTypes { get; set; }
    [JsonPropertyName("response_types"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] public IEnumerable<string>? ResponseTypes { get; set; }
    [JsonPropertyName("token_endpoint_auth_method"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] public string? TokenEndpointAuthMethod { get; set; }
    [JsonPropertyName("scope"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] public string? Scope { get; set; }
}

public static class DynamicClientRegistrationValidation
{
    private static readonly HashSet<string> SupportedGrantTypes = new(StringComparer.OrdinalIgnoreCase)
    {
        "authorization_code","client_credentials","refresh_token"
    };
    private static readonly HashSet<string> SupportedResponseTypes = new(StringComparer.OrdinalIgnoreCase) { "code" };

    public static (bool ok, string? error) Validate(DynamicClientRegistrationRequest req)
    {
        if (req == null)
        {
            return (false, "invalid_request");
        }
        // Require authorization_code or client_credentials at least one
        var grants = req.GrantTypes ?? new List<string>();
        if (grants.Count == 0)
        {
            return (false, "At least one grant_type required");
        }

        if (grants.Any(g => !SupportedGrantTypes.Contains(g)))
        {
            return (false, "Unsupported grant_type");
        }

        if (grants.Contains("authorization_code", StringComparer.OrdinalIgnoreCase))
        {
            if (req.RedirectUris is null || req.RedirectUris.Count == 0)
            {
                return (false, "redirect_uris required for authorization_code grant");
            }

            var responses = req.ResponseTypes ?? new List<string> { "code" };
            if (responses.Any(r => !SupportedResponseTypes.Contains(r)))
            {
                return (false, "Unsupported response_type");
            }
        }
        if (req.GrantTypes?.Contains("password", StringComparer.OrdinalIgnoreCase) == true)
        {
            return (false, "password grant not allowed");
        }

        if (!string.IsNullOrWhiteSpace(req.Scope) && req.Scope!.Split(' ', StringSplitOptions.RemoveEmptyEntries).Length > 50)
        {
            return (false, "Too many scopes requested");
        }

        return (true, null);
    }
}
