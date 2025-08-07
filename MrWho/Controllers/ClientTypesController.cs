using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using MrWho.Shared;
using MrWho.Shared.Models;

namespace MrWho.Controllers;

[ApiController]
[Route("api/[controller]")]
[Authorize]
public class ClientTypesController : ControllerBase
{
    private readonly ILogger<ClientTypesController> _logger;

    public ClientTypesController(ILogger<ClientTypesController> logger)
    {
        _logger = logger;
    }

    /// <summary>
    /// Get all available client types with their descriptions and characteristics
    /// </summary>
    [HttpGet]
    public ActionResult<IEnumerable<ClientTypeInfoDto>> GetClientTypes()
    {
        var clientTypes = new List<ClientTypeInfoDto>
        {
            new()
            {
                Type = ClientType.Confidential,
                Name = "Confidential Client",
                Description = "Server-side applications that can securely store credentials",
                Characteristics = new List<string>
                {
                    "Can securely store client secret",
                    "Typically web applications running on servers",
                    "Examples: ASP.NET web apps, server-side rendered applications",
                    "Supports Authorization Code flow",
                    "Requires client authentication"
                },
                RecommendedFlows = new List<string>
                {
                    "Authorization Code Flow",
                    "Client Credentials Flow (for machine-to-machine)",
                    "Refresh Token Flow"
                },
                SecurityConsiderations = new List<string>
                {
                    "Must protect client secret",
                    "Should use HTTPS for all communications",
                    "Can use PKCE for additional security"
                },
                UseCases = new List<string>
                {
                    "Traditional web applications",
                    "Server-side APIs",
                    "Backend services with user interaction"
                }
            },
            new()
            {
                Type = ClientType.Public,
                Name = "Public Client",
                Description = "Client applications that cannot securely store credentials",
                Characteristics = new List<string>
                {
                    "Cannot securely store client secret",
                    "Typically mobile apps, SPAs, or desktop applications",
                    "Examples: React SPAs, mobile apps, desktop applications",
                    "Must use PKCE for security",
                    "No client authentication required"
                },
                RecommendedFlows = new List<string>
                {
                    "Authorization Code Flow with PKCE",
                    "Refresh Token Flow (with rotation)"
                },
                SecurityConsiderations = new List<string>
                {
                    "PKCE is mandatory for security",
                    "Refresh token rotation recommended",
                    "Short access token lifetime recommended",
                    "No client secret should be used"
                },
                UseCases = new List<string>
                {
                    "Single Page Applications (SPAs)",
                    "Mobile applications",
                    "Desktop applications",
                    "Client-side JavaScript applications"
                }
            },
            new()
            {
                Type = ClientType.Machine,
                Name = "Machine-to-Machine Client",
                Description = "Server applications that act on their own behalf, not on behalf of users",
                Characteristics = new List<string>
                {
                    "No user interaction required",
                    "Authenticates using client credentials",
                    "Examples: APIs calling other APIs, background services",
                    "Uses Client Credentials flow exclusively",
                    "Requires client authentication"
                },
                RecommendedFlows = new List<string>
                {
                    "Client Credentials Flow"
                },
                SecurityConsiderations = new List<string>
                {
                    "Must protect client secret",
                    "Use certificate-based authentication when possible",
                    "Limit scope to minimum required permissions",
                    "Regular credential rotation recommended"
                },
                UseCases = new List<string>
                {
                    "API-to-API communication",
                    "Background services",
                    "Automated systems",
                    "Microservices communication",
                    "Scheduled jobs and processes"
                }
            }
        };

        return Ok(clientTypes);
    }

    /// <summary>
    /// Get specific client type information
    /// </summary>
    [HttpGet("{type}")]
    public ActionResult<ClientTypeInfoDto> GetClientType(ClientType type)
    {
        var clientTypes = GetClientTypes().Value as IEnumerable<ClientTypeInfoDto>;
        var clientType = clientTypes?.FirstOrDefault(ct => ct.Type == type);

        if (clientType == null)
        {
            return NotFound($"Client type '{type}' not found");
        }

        return Ok(clientType);
    }
}