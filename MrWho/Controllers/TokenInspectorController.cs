using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text.Json;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;

namespace MrWho.Controllers;

[ApiController]
[Route("identity/[controller]")]
[Route("identity/token-inspector")] // Add explicit route for the kebab-case URL
public class TokenInspectorController : ControllerBase
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
        var html = GenerateTokenInspectorHtml();
        return Content(html, "text/html");
    }

    /// <summary>
    /// API endpoint for decoding and inspecting JWT tokens
    /// </summary>
    [HttpPost("decode")]
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
    [Authorize] // Require authorization for introspection
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
    [Authorize]
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

    private static string GenerateTokenInspectorHtml()
    {
        return """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>JWT Token Inspector - MrWho Identity Server</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 10px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.1);
            overflow: hidden;
        }
        
        .header {
            background: linear-gradient(135deg, #2c3e50 0%, #34495e 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }
        
        .header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
        }
        
        .header p {
            opacity: 0.9;
            font-size: 1.1em;
        }
        
        .content {
            padding: 30px;
        }
        
        .form-group {
            margin-bottom: 20px;
        }
        
        label {
            display: block;
            margin-bottom: 8px;
            font-weight: 600;
            color: #555;
        }
        
        textarea, input[type="text"] {
            width: 100%;
            padding: 12px;
            border: 2px solid #e1e8ed;
            border-radius: 8px;
            font-family: 'Courier New', monospace;
            font-size: 14px;
            transition: border-color 0.3s ease;
        }
        
        textarea:focus, input[type="text"]:focus {
            outline: none;
            border-color: #667eea;
        }
        
        textarea {
            min-height: 120px;
            resize: vertical;
        }
        
        .button-group {
            display: flex;
            gap: 15px;
            margin-bottom: 30px;
            flex-wrap: wrap;
        }
        
        button {
            padding: 12px 24px;
            border: none;
            border-radius: 8px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
            min-width: 120px;
        }
        
        .btn-primary {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
        }
        
        .btn-secondary {
            background: #6c757d;
            color: white;
        }
        
        .btn-success {
            background: #28a745;
            color: white;
        }
        
        .btn-info {
            background: #17a2b8;
            color: white;
        }
        
        button:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(0,0,0,0.2);
        }
        
        button:disabled {
            opacity: 0.6;
            cursor: not-allowed;
            transform: none;
        }
        
        .result {
            margin-top: 30px;
            padding: 25px;
            border-radius: 8px;
            display: none;
        }
        
        .result.success {
            background: #d4edda;
            border: 1px solid #c3e6cb;
            color: #155724;
        }
        
        .result.error {
            background: #f8d7da;
            border: 1px solid #f5c6cb;
            color: #721c24;
        }
        
        .token-info {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }
        
        .info-section {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            border-left: 4px solid #667eea;
        }
        
        .info-section h3 {
            margin-bottom: 15px;
            color: #2c3e50;
            font-size: 1.2em;
        }
        
        .info-item {
            margin-bottom: 10px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 8px 0;
            border-bottom: 1px solid #e9ecef;
        }
        
        .info-item:last-child {
            border-bottom: none;
        }
        
        .info-label {
            font-weight: 600;
            color: #555;
            flex: 0 0 40%;
        }
        
        .info-value {
            flex: 1;
            text-align: right;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            word-break: break-all;
        }
        
        .claims-list {
            max-height: 300px;
            overflow-y: auto;
            background: white;
            border: 1px solid #e9ecef;
            border-radius: 4px;
            padding: 10px;
        }
        
        .claim-item {
            padding: 8px;
            border-bottom: 1px solid #f1f3f4;
            font-family: 'Courier New', monospace;
            font-size: 0.85em;
        }
        
        .claim-type {
            font-weight: 600;
            color: #495057;
        }
        
        .claim-value {
            color: #6c757d;
            margin-left: 10px;
        }
        
        .validity-indicator {
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.8em;
            font-weight: 600;
            text-transform: uppercase;
        }
        
        .valid {
            background: #d4edda;
            color: #155724;
        }
        
        .expired {
            background: #f8d7da;
            color: #721c24;
        }
        
        .not-yet-valid {
            background: #fff3cd;
            color: #856404;
        }
        
        .loading {
            text-align: center;
            color: #6c757d;
        }
        
        .example-tokens {
            margin-top: 20px;
            padding: 20px;
            background: #f8f9fa;
            border-radius: 8px;
            border-left: 4px solid #17a2b8;
        }
        
        .example-tokens h3 {
            margin-bottom: 15px;
            color: #2c3e50;
        }
        
        .example-token {
            margin-bottom: 10px;
            padding: 10px;
            background: white;
            border-radius: 4px;
            border: 1px solid #e9ecef;
            cursor: pointer;
            transition: background-color 0.2s ease;
        }
        
        .example-token:hover {
            background: #e3f2fd;
        }
        
        .example-token-label {
            font-weight: 600;
            color: #495057;
            margin-bottom: 5px;
        }
        
        .example-token-value {
            font-family: 'Courier New', monospace;
            font-size: 0.8em;
            color: #6c757d;
            word-break: break-all;
        }
        
        @media (max-width: 768px) {
            .button-group {
                flex-direction: column;
            }
            
            .info-item {
                flex-direction: column;
                align-items: flex-start;
            }
            
            .info-value {
                text-align: left;
                margin-top: 5px;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 JWT Token Inspector</h1>
            <p>Decode and inspect JWT tokens securely</p>
        </div>
        
        <div class="content">
            <div class="form-group">
                <label for="tokenInput">JWT Token:</label>
                <textarea id="tokenInput" placeholder="Paste your JWT token here (with or without 'Bearer ' prefix)..."></textarea>
            </div>
            
            <div class="button-group">
                <button class="btn-primary" onclick="decodeToken()">🔍 Decode Token</button>
                <button class="btn-secondary" onclick="clearToken()">🗑️ Clear</button>
                <button class="btn-success" onclick="getCurrentToken()">👤 Get Current Token</button>
                <button class="btn-info" onclick="introspectToken()">🔎 Introspect Token</button>
            </div>
            
            <div id="result" class="result">
                <div id="resultContent"></div>
            </div>
            
            <div class="example-tokens">
                <h3>🎯 Quick Actions</h3>
                <div class="example-token" onclick="getCurrentToken()">
                    <div class="example-token-label">Current User Token</div>
                    <div class="example-token-value">Click to inspect your current authentication token</div>
                </div>
                <div class="example-token" onclick="showSampleToken()">
                    <div class="example-token-label">Sample JWT Token</div>
                    <div class="example-token-value">Click to load a sample token for demonstration</div>
                </div>
            </div>
        </div>
    </div>

    <script>
        const API_BASE = window.location.origin + '/identity/token-inspector';
        
        async function decodeToken() {
            const token = document.getElementById('tokenInput').value.trim();
            if (!token) {
                showError('Please enter a JWT token');
                return;
            }
            
            showLoading();
            
            try {
                const response = await fetch(`${API_BASE}/decode`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({ token: token })
                });
                
                const data = await response.json();
                
                if (response.ok) {
                    showTokenInfo(data);
                } else {
                    showError(data.error || 'Failed to decode token');
                }
            } catch (error) {
                showError('Network error: ' + error.message);
            }
        }
        
        async function introspectToken() {
            const token = document.getElementById('tokenInput').value.trim();
            if (!token) {
                showError('Please enter a JWT token');
                return;
            }
            
            showLoading();
            
            try {
                const response = await fetch(`${API_BASE}/introspect`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': `Bearer ${token}`
                    },
                    body: JSON.stringify({ token: token })
                });
                
                const data = await response.json();
                
                if (response.ok) {
                    showIntrospectionResult(data);
                } else {
                    showError('Failed to introspect token');
                }
            } catch (error) {
                showError('Network error: ' + error.message);
            }
        }
        
        async function getCurrentToken() {
            showLoading();
            
            try {
                const response = await fetch(`${API_BASE}/current`, {
                    method: 'GET',
                    credentials: 'same-origin'
                });
                
                if (response.status === 401) {
                    showError('You are not authenticated. Please log in first.');
                    return;
                }
                
                const data = await response.json();
                
                if (response.ok) {
                    showCurrentTokenInfo(data);
                } else {
                    showError('Failed to get current token info');
                }
            } catch (error) {
                showError('Network error: ' + error.message);
            }
        }
        
        function clearToken() {
            document.getElementById('tokenInput').value = '';
            hideResult();
        }
        
        function showSampleToken() {
            // This is a sample JWT token (header.payload.signature format)
            const sampleToken = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJleHAiOjk5OTk5OTk5OTksInNjb3BlIjoib3BlbmlkIGVtYWlsIHByb2ZpbGUiLCJjbGllbnRfaWQiOiJzYW1wbGVfY2xpZW50In0.4Adcj3UFYzPUVaVF43FmMab6RlaQD8A9V8wFzzht-bE';
            document.getElementById('tokenInput').value = sampleToken;
        }
        
        function showLoading() {
            const result = document.getElementById('result');
            const content = document.getElementById('resultContent');
            
            content.innerHTML = '<div class="loading">🔄 Processing...</div>';
            result.className = 'result';
            result.style.display = 'block';
        }
        
        function showError(message) {
            const result = document.getElementById('result');
            const content = document.getElementById('resultContent');
            
            content.innerHTML = `<h3>❌ Error</h3><p>${message}</p>`;
            result.className = 'result error';
            result.style.display = 'block';
        }
        
        function hideResult() {
            document.getElementById('result').style.display = 'none';
        }
        
        function showTokenInfo(data) {
            const result = document.getElementById('result');
            const content = document.getElementById('resultContent');
            
            const validityClass = data.validity.isValid ? 'valid' : 
                                  data.validity.isExpired ? 'expired' : 'not-yet-valid';
            const validityText = data.validity.isValid ? 'Valid' : 
                                data.validity.isExpired ? 'Expired' : 'Not Yet Valid';
            
            content.innerHTML = `
                <h3>✅ Token Decoded Successfully</h3>
                <div class="token-info">
                    <div class="info-section">
                        <h3>📋 Header</h3>
                        <div class="info-item">
                            <span class="info-label">Algorithm:</span>
                            <span class="info-value">${data.header.alg}</span>
                        </div>
                        <div class="info-item">
                            <span class="info-label">Type:</span>
                            <span class="info-value">${data.header.typ}</span>
                        </div>
                        ${data.header.kid ? `
                        <div class="info-item">
                            <span class="info-label">Key ID:</span>
                            <span class="info-value">${data.header.kid}</span>
                        </div>` : ''}
                    </div>
                    
                    <div class="info-section">
                        <h3>🎯 Payload</h3>
                        <div class="info-item">
                            <span class="info-label">Issuer:</span>
                            <span class="info-value">${data.payload.iss || 'N/A'}</span>
                        </div>
                        <div class="info-item">
                            <span class="info-label">Subject:</span>
                            <span class="info-value">${data.payload.sub || 'N/A'}</span>
                        </div>
                        <div class="info-item">
                            <span class="info-label">Audience:</span>
                            <span class="info-value">${Array.isArray(data.payload.aud) ? data.payload.aud.join(', ') : (data.payload.aud || 'N/A')}</span>
                        </div>
                        ${data.payload.jti ? `
                        <div class="info-item">
                            <span class="info-label">Token ID:</span>
                            <span class="info-value">${data.payload.jti}</span>
                        </div>` : ''}
                    </div>
                    
                    <div class="info-section">
                        <h3>⏰ Validity</h3>
                        <div class="info-item">
                            <span class="info-label">Status:</span>
                            <span class="validity-indicator ${validityClass}">${validityText}</span>
                        </div>
                        <div class="info-item">
                            <span class="info-label">Valid From:</span>
                            <span class="info-value">${data.validity.validFrom}</span>
                        </div>
                        <div class="info-item">
                            <span class="info-label">Valid To:</span>
                            <span class="info-value">${data.validity.validTo}</span>
                        </div>
                        <div class="info-item">
                            <span class="info-label">Time Until Expiry:</span>
                            <span class="info-value">${data.validity.timeUntilExpiry}</span>
                        </div>
                    </div>
                    
                    <div class="info-section">
                        <h3>📊 Metadata</h3>
                        <div class="info-item">
                            <span class="info-label">Token Type:</span>
                            <span class="info-value">${data.metadata.tokenType}</span>
                        </div>
                        <div class="info-item">
                            <span class="info-label">Token Length:</span>
                            <span class="info-value">${data.metadata.tokenLength} chars</span>
                        </div>
                        <div class="info-item">
                            <span class="info-label">Claims Count:</span>
                            <span class="info-value">${data.metadata.claimsCount}</span>
                        </div>
                        <div class="info-item">
                            <span class="info-label">Audience Count:</span>
                            <span class="info-value">${data.metadata.audienceCount}</span>
                        </div>
                    </div>
                </div>
                
                ${data.payload.claims && data.payload.claims.length > 0 ? `
                <div class="info-section" style="grid-column: 1 / -1; margin-top: 20px;">
                    <h3>🏷️ All Claims (${data.payload.claims.length})</h3>
                    <div class="claims-list">
                        ${data.payload.claims.map(claim => `
                            <div class="claim-item">
                                <span class="claim-type">${claim.type}:</span>
                                <span class="claim-value">${claim.value}</span>
                            </div>
                        `).join('')}
                    </div>
                </div>` : ''}
            `;
            
            result.className = 'result success';
            result.style.display = 'block';
        }
        
        function showIntrospectionResult(data) {
            const result = document.getElementById('result');
            const content = document.getElementById('resultContent');
            
            if (data.active) {
                content.innerHTML = `
                    <h3>✅ Token Introspection Result</h3>
                    <div class="token-info">
                        <div class="info-section">
                            <h3>🔍 Introspection Result</h3>
                            <div class="info-item">
                                <span class="info-label">Active:</span>
                                <span class="validity-indicator valid">True</span>
                            </div>
                            <div class="info-item">
                                <span class="info-label">Client ID:</span>
                                <span class="info-value">${data.client_id || 'N/A'}</span>
                            </div>
                            <div class="info-item">
                                <span class="info-label">Username:</span>
                                <span class="info-value">${data.username || 'N/A'}</span>
                            </div>
                            <div class="info-item">
                                <span class="info-label">Subject:</span>
                                <span class="info-value">${data.sub || 'N/A'}</span>
                            </div>
                            <div class="info-item">
                                <span class="info-label">Scope:</span>
                                <span class="info-value">${data.scope || 'N/A'}</span>
                            </div>
                            <div class="info-item">
                                <span class="info-label">Token Type:</span>
                                <span class="info-value">${data.token_type || 'N/A'}</span>
                            </div>
                            <div class="info-item">
                                <span class="info-label">Token Use:</span>
                                <span class="info-value">${data.token_use || 'N/A'}</span>
                            </div>
                        </div>
                    </div>
                `;
                result.className = 'result success';
            } else {
                content.innerHTML = `
                    <h3>❌ Token Introspection Result</h3>
                    <div class="info-item">
                        <span class="info-label">Active:</span>
                        <span class="validity-indicator expired">False</span>
                    </div>
                    ${data.error ? `<p>Error: ${data.error}</p>` : ''}
                `;
                result.className = 'result error';
            }
            
            result.style.display = 'block';
        }
        
        function showCurrentTokenInfo(data) {
            const result = document.getElementById('result');
            const content = document.getElementById('resultContent');
            
            content.innerHTML = `
                <h3>👤 Current User Token Information</h3>
                <div class="token-info">
                    <div class="info-section">
                        <h3>🔐 Authentication</h3>
                        <div class="info-item">
                            <span class="info-label">Authenticated:</span>
                            <span class="validity-indicator ${data.isAuthenticated ? 'valid' : 'expired'}">${data.isAuthenticated}</span>
                        </div>
                        <div class="info-item">
                            <span class="info-label">Type:</span>
                            <span class="info-value">${data.authenticationType || 'N/A'}</span>
                        </div>
                        <div class="info-item">
                            <span class="info-label">Name:</span>
                            <span class="info-value">${data.name || 'N/A'}</span>
                        </div>
                        <div class="info-item">
                            <span class="info-label">Subject:</span>
                            <span class="info-value">${data.subject || 'N/A'}</span>
                        </div>
                        <div class="info-item">
                            <span class="info-label">Email:</span>
                            <span class="info-value">${data.email || 'N/A'}</span>
                        </div>
                    </div>
                    
                    <div class="info-section">
                        <h3>🎯 Authorization</h3>
                        <div class="info-item">
                            <span class="info-label">Client ID:</span>
                            <span class="info-value">${data.clientId || 'N/A'}</span>
                        </div>
                        <div class="info-item">
                            <span class="info-label">Issuer:</span>
                            <span class="info-value">${data.issuer || 'N/A'}</span>
                        </div>
                        <div class="info-item">
                            <span class="info-label">Audience:</span>
                            <span class="info-value">${data.audience && data.audience.length > 0 ? data.audience.join(', ') : 'N/A'}</span>
                        </div>
                        <div class="info-item">
                            <span class="info-label">Token Expiry:</span>
                            <span class="info-value">${data.tokenExpiry || 'N/A'}</span>
                        </div>
                    </div>
                    
                    <div class="info-section">
                        <h3>📊 Statistics</h3>
                        <div class="info-item">
                            <span class="info-label">Total Claims:</span>
                            <span class="info-value">${data.claimsCount}</span>
                        </div>
                        <div class="info-item">
                            <span class="info-label">Roles Count:</span>
                            <span class="info-value">${data.metadata.rolesCount}</span>
                        </div>
                        <div class="info-item">
                            <span class="info-label">Scopes Count:</span>
                            <span class="info-value">${data.metadata.scopesCount}</span>
                        </div>
                        <div class="info-item">
                            <span class="info-label">Has Subject:</span>
                            <span class="validity-indicator ${data.metadata.hasSubject ? 'valid' : 'expired'}">${data.metadata.hasSubject}</span>
                        </div>
                        <div class="info-item">
                            <span class="info-label">Has Email:</span>
                            <span class="validity-indicator ${data.metadata.hasEmail ? 'valid' : 'expired'}">${data.metadata.hasEmail}</span>
                        </div>
                    </div>
                </div>
                
                ${data.roles && data.roles.length > 0 ? `
                <div class="info-section" style="grid-column: 1 / -1; margin-top: 20px;">
                    <h3>👥 Roles (${data.roles.length})</h3>
                    <div class="claims-list">
                        ${data.roles.map(role => `
                            <div class="claim-item">
                                <span class="claim-type">Role:</span>
                                <span class="claim-value">${role}</span>
                            </div>
                        `).join('')}
                    </div>
                </div>` : ''}
                
                ${data.scopes && data.scopes.length > 0 ? `
                <div class="info-section" style="grid-column: 1 / -1; margin-top: 20px;">
                    <h3>🔑 Scopes (${data.scopes.length})</h3>
                    <div class="claims-list">
                        ${data.scopes.map(scope => `
                            <div class="claim-item">
                                <span class="claim-type">Scope:</span>
                                <span class="claim-value">${scope}</span>
                            </div>
                        `).join('')}
                    </div>
                </div>` : ''}
                
                ${data.claims && data.claims.length > 0 ? `
                <div class="info-section" style="grid-column: 1 / -1; margin-top: 20px;">
                    <h3>🏷️ All Claims (${data.claims.length})</h3>
                    <div class="claims-list">
                        ${data.claims.map(claim => `
                            <div class="claim-item">
                                <span class="claim-type">${claim.type}:</span>
                                <span class="claim-value">${claim.value}</span>
                            </div>
                        `).join('')}
                    </div>
                </div>` : ''}
            `;
            
            result.className = 'result success';
            result.style.display = 'block';
        }
        
        // Allow Enter key to decode token
        document.getElementById('tokenInput').addEventListener('keypress', function(e) {
            if (e.key === 'Enter' && e.ctrlKey) {
                decodeToken();
            }
        });
        
        // Auto-focus on token input
        document.getElementById('tokenInput').focus();
    </script>
</body>
</html>
""";
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