using Microsoft.AspNetCore.Mvc;

namespace MrWho.ApiService.Controllers;

[ApiController]
[Route(".well-known")]
public class WellKnownController : ControllerBase
{
    private readonly IConfiguration _configuration;
    private readonly ILogger<WellKnownController> _logger;

    public WellKnownController(IConfiguration configuration, ILogger<WellKnownController> logger)
    {
        _configuration = configuration;
        _logger = logger;
    }

    [HttpGet("endpoints")]
    [Produces("application/json")]
    public IActionResult GetEndpoints()
    {
        var baseUrl = $"{Request.Scheme}://{Request.Host}";
        
        return Ok(new
        {
            issuer = baseUrl,
            authorization_endpoint = $"{baseUrl}/connect/authorize",
            token_endpoint = $"{baseUrl}/connect/token",
            userinfo_endpoint = $"{baseUrl}/connect/userinfo",
            introspection_endpoint = $"{baseUrl}/connect/introspect",
            revocation_endpoint = $"{baseUrl}/connect/revoke",
            jwks_uri = $"{baseUrl}/.well-known/jwks",
            configuration_endpoint = $"{baseUrl}/.well-known/openid_configuration",
            
            // Login/Logout UI endpoints
            login_url = $"{baseUrl}/Account/Login",
            logout_url = $"{baseUrl}/Account/Logout",
            
            // Management endpoints
            users_endpoint = $"{baseUrl}/api/users",
            test_endpoints = new
            {
                public_test = $"{baseUrl}/api/test/public",
                protected_test = $"{baseUrl}/api/test/protected",
                user_info_test = $"{baseUrl}/api/test/user-info"
            },
            
            // Supported flows and features
            supported_flows = new[]
            {
                "authorization_code",
                "password",
                "client_credentials",
                "refresh_token"
            },
            supported_scopes = new[]
            {
                "openid",
                "profile", 
                "email",
                "roles"
            },
            supported_response_types = new[]
            {
                "code"
            },
            
            // Client configurations
            sample_clients = new
            {
                web_client = new
                {
                    client_id = "mrwho-web-client",
                    client_secret = "mrwho-web-secret",
                    grant_types = new[] { "authorization_code" },
                    redirect_uris = new[]
                    {
                        "https://localhost:5000/signin-oidc",
                        "https://localhost:5001/signin-oidc"
                    }
                },
                spa_client = new
                {
                    client_id = "mrwho-spa-client",
                    grant_types = new[] { "authorization_code" },
                    redirect_uris = new[]
                    {
                        "https://localhost:3000/callback",
                        "https://localhost:4200/callback"
                    }
                },
                server_client = new
                {
                    client_id = "mrwho-client",
                    client_secret = "mrwho-secret",
                    grant_types = new[] { "password", "client_credentials" }
                }
            }
        });
    }
}