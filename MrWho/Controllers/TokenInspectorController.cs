using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text.Json;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using MrWho.Shared;

namespace MrWho.Controllers;

[Authorize] // Require authenticated users for all actions in this controller
[Route("identity/[controller]")]
[Route("identity/token-inspector")] // Add explicit route for the kebab-case URL
public class TokenInspectorController : Controller // Changed from ControllerBase to Controller
{
    private readonly ILogger<TokenInspectorController> _logger;
    private readonly JwtSecurityTokenHandler _jwtHandler;

    public TokenInspectorController(ILogger<TokenInspectorController> logger)
    {
        _logger = logger;
        _jwtHandler = new JwtSecurityTokenHandler();
    }

    /// <summary>
    /// Token inspector endpoint - provides a UI for inspecting JWT tokens
    /// </summary>
    [HttpGet()]
    public IActionResult Index()
    {
        return View(); // Return a Razor view instead of HTML string
    }

    /// <summary>
    /// API endpoint for decoding and inspecting JWT tokens
    /// </summary>
    [HttpPost("decode")]
    [Authorize] // Only require authentication for token inspection
    public IActionResult DecodeToken([FromBody] DecodeTokenRequest request)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(request.Token))
            {
                return BadRequest(new { error = "Token is required" });
            }

            // Remove "Bearer " prefix if present
            var token = request.Token.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase)
                ? request.Token.Substring(7)
                : request.Token;

            if (!_jwtHandler.CanReadToken(token))
            {
                return BadRequest(new { error = "Invalid JWT token format" });
            }

            var jwtToken = _jwtHandler.ReadJwtToken(token);

            var decodedToken = new
            {
                header = new
                {
                    alg = jwtToken.Header.Alg,
                    typ = jwtToken.Header.Typ,
                    kid = jwtToken.Header.Kid,
                    x5t = jwtToken.Header.X5t,
                    additionalHeaders = jwtToken.Header.Where(h => !new[] { "alg", "typ", "kid", "x5t" }.Contains(h.Key))
                        .ToDictionary(h => h.Key, h => h.Value)
                },
                payload = new
                {
                    iss = jwtToken.Issuer,
                    sub = jwtToken.Subject,
                    aud = jwtToken.Audiences.ToList(),
                    exp = jwtToken.ValidTo != DateTime.MinValue ? ((DateTimeOffset)jwtToken.ValidTo).ToUnixTimeSeconds() : (long?)null,
                    nbf = jwtToken.ValidFrom != DateTime.MinValue ? ((DateTimeOffset)jwtToken.ValidFrom).ToUnixTimeSeconds() : (long?)null,
                    iat = jwtToken.IssuedAt != DateTime.MinValue ? ((DateTimeOffset)jwtToken.IssuedAt).ToUnixTimeSeconds() : (long?)null,
                    jti = jwtToken.Id,
                    claims = jwtToken.Claims.Select(c => new { type = c.Type, value = c.Value }).ToList(),
                    customClaims = jwtToken.Claims
                        .Where(c => !IsStandardClaim(c.Type))
                        .Select(c => new { type = c.Type, value = c.Value })
                        .ToList()
                },
                validity = new
                {
                    isValid = jwtToken.ValidTo > DateTime.UtcNow && jwtToken.ValidFrom <= DateTime.UtcNow,
                    isExpired = jwtToken.ValidTo <= DateTime.UtcNow,
                    isNotYetValid = jwtToken.ValidFrom > DateTime.UtcNow,
                    validFrom = jwtToken.ValidFrom.ToString("yyyy-MM-dd HH:mm:ss UTC"),
                    validTo = jwtToken.ValidTo.ToString("yyyy-MM-dd HH:mm:ss UTC"),
                    timeUntilExpiry = jwtToken.ValidTo > DateTime.UtcNow 
                        ? (jwtToken.ValidTo - DateTime.UtcNow).ToString(@"dd\:hh\:mm\:ss")
                        : "Expired"
                },
                metadata = new
                {
                    tokenLength = token.Length,
                    claimsCount = jwtToken.Claims.Count(),
                    audienceCount = jwtToken.Audiences.Count(),
                    hasSubject = !string.IsNullOrEmpty(jwtToken.Subject),
                    hasIssuer = !string.IsNullOrEmpty(jwtToken.Issuer),
                    tokenType = GetTokenType(jwtToken)
                }
            };

            return Ok(decodedToken);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error decoding JWT token");
            return BadRequest(new { error = $"Error decoding token: {ex.Message}" });
        }
    }

    /// <summary>
    /// Introspect token endpoint - validates and provides information about a token
    /// This mimics OAuth 2.0 token introspection (RFC 7662)
    /// </summary>
    [HttpPost("introspect")]
    [Authorize] // Only require authentication
    public IActionResult IntrospectToken([FromBody] IntrospectTokenRequest request)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(request.Token))
            {
                return BadRequest(new { error = "token parameter is required" });
            }

            // Remove "Bearer " prefix if present
            var token = request.Token.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase)
                ? request.Token.Substring(7)
                : request.Token;

            // First, try to decode the token to check basic validity
            if (!_jwtHandler.CanReadToken(token))
            {
                return Ok(new { active = false });
            }

            var jwtToken = _jwtHandler.ReadJwtToken(token);

            // Check if token is expired
            if (jwtToken.ValidTo <= DateTime.UtcNow)
            {
                return Ok(new { active = false, error = "token_expired" });
            }

            // Check if token is not yet valid
            if (jwtToken.ValidFrom > DateTime.UtcNow)
            {
                return Ok(new { active = false, error = "token_not_yet_valid" });
            }

            // Token appears to be active
            var introspectionResult = new
            {
                active = true,
                client_id = jwtToken.Claims.FirstOrDefault(c => c.Type == "client_id")?.Value,
                username = jwtToken.Claims.FirstOrDefault(c => c.Type == "preferred_username")?.Value ?? jwtToken.Subject,
                scope = string.Join(" ", jwtToken.Claims.Where(c => c.Type == "scope").Select(c => c.Value)),
                sub = jwtToken.Subject,
                aud = jwtToken.Audiences.ToArray(),
                iss = jwtToken.Issuer,
                exp = jwtToken.ValidTo != DateTime.MinValue ? ((DateTimeOffset)jwtToken.ValidTo).ToUnixTimeSeconds() : (long?)null,
                iat = jwtToken.IssuedAt != DateTime.MinValue ? ((DateTimeOffset)jwtToken.IssuedAt).ToUnixTimeSeconds() : (long?)null,
                nbf = jwtToken.ValidFrom != DateTime.MinValue ? ((DateTimeOffset)jwtToken.ValidFrom).ToUnixTimeSeconds() : (long?)null,
                jti = jwtToken.Id,
                token_type = "Bearer",
                token_use = GetTokenType(jwtToken)
            };

            return Ok(introspectionResult);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error introspecting token");
            return Ok(new { active = false, error = "invalid_token" });
        }
    }

    /// <summary>
    /// Current user's token information endpoint
    /// </summary>
    [HttpGet("current")]
    [Authorize] // Only require authentication
    public IActionResult GetCurrentTokenInfo()
    {
        try
        {
            var principal = HttpContext.User;
            if (principal?.Identity?.IsAuthenticated != true)
            {
                return Unauthorized();
            }

            var claims = principal.Claims.Select(c => new { type = c.Type, value = c.Value }).ToList();
            
            var tokenInfo = new
            {
                isAuthenticated = principal.Identity.IsAuthenticated,
                authenticationType = principal.Identity.AuthenticationType,
                name = principal.Identity.Name,
                subject = principal.FindFirst(ClaimTypes.NameIdentifier)?.Value ?? 
                         principal.FindFirst("sub")?.Value,
                email = principal.FindFirst(ClaimTypes.Email)?.Value,
                roles = principal.FindAll(ClaimTypes.Role).Select(c => c.Value).ToList(),
                scopes = principal.FindAll("scope").Select(c => c.Value).ToList(),
                clientId = principal.FindFirst("client_id")?.Value,
                issuer = principal.FindFirst("iss")?.Value,
                audience = principal.FindAll("aud").Select(c => c.Value).ToList(),
                claims = claims,
                claimsCount = claims.Count,
                tokenExpiry = GetTokenExpiry(principal),
                metadata = new
                {
                    hasSubject = !string.IsNullOrEmpty(principal.FindFirst("sub")?.Value),
                    hasEmail = !string.IsNullOrEmpty(principal.FindFirst(ClaimTypes.Email)?.Value),
                    rolesCount = principal.FindAll(ClaimTypes.Role).Count(),
                    scopesCount = principal.FindAll("scope").Count()
                }
            };

            return Ok(tokenInfo);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting current token info");
            return Problem("Error retrieving token information");
        }
    }

    private static bool IsStandardClaim(string claimType)
    {
        var standardClaims = new[]
        {
            "iss", "sub", "aud", "exp", "nbf", "iat", "jti", "azp", "scope",
            "client_id", "token_type", "preferred_username", "given_name",
            "family_name", "name", "email", "email_verified", "phone_number",
            "phone_number_verified", "address", "updated_at", "locale",
            "zoneinfo", "birthdate", "gender", "website", "picture", "profile",
            ClaimTypes.NameIdentifier, ClaimTypes.Name, ClaimTypes.Email,
            ClaimTypes.Role, ClaimTypes.GivenName, ClaimTypes.Surname
        };

        return standardClaims.Contains(claimType);
    }

    private static string GetTokenType(JwtSecurityToken token)
    {
        // Check token usage patterns to determine type
        var scopes = token.Claims.Where(c => c.Type == "scope").Select(c => c.Value).ToList();
        var hasOpenId = scopes.Contains("openid");
        var hasApiScopes = scopes.Any(s => s.StartsWith("api."));

        if (hasOpenId && hasApiScopes)
            return "hybrid";
        else if (hasOpenId)
            return "id_token";
        else if (hasApiScopes)
            return "access_token";
        else
            return "unknown";
    }

    private static string? GetTokenExpiry(ClaimsPrincipal principal)
    {
        var expClaim = principal.FindFirst("exp")?.Value;
        if (expClaim != null && long.TryParse(expClaim, out var expUnix))
        {
            var expDateTime = DateTimeOffset.FromUnixTimeSeconds(expUnix);
            return expDateTime.ToString("yyyy-MM-dd HH:mm:ss UTC");
        }
        return null;
    }

    public class DecodeTokenRequest
    {
        public string Token { get; set; } = string.Empty;
    }

    public class IntrospectTokenRequest
    {
        public string Token { get; set; } = string.Empty;
    }
}