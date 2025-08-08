using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using MrWhoAdmin.Web.Services;

namespace MrWhoAdmin.Web.Controllers;

/// <summary>
/// Controller for health checks and diagnostics
/// </summary>
[Route("api/[controller]")]
[ApiController]
public class HealthController : ControllerBase
{
    private readonly IRealmsApiService _realmsApiService;
    private readonly ILogger<HealthController> _logger;

    public HealthController(IRealmsApiService realmsApiService, ILogger<HealthController> logger)
    {
        _realmsApiService = realmsApiService;
        _logger = logger;
    }

    /// <summary>
    /// Basic health check endpoint
    /// </summary>
    [HttpGet]
    public IActionResult Get()
    {
        return Ok(new
        {
            status = "healthy",
            timestamp = DateTime.UtcNow,
            version = "1.0.0"
        });
    }

    /// <summary>
    /// Health check with MrWho API connectivity test
    /// </summary>
    [HttpGet("detailed")]
    [Authorize]
    public async Task<IActionResult> GetDetailed()
    {
        var healthStatus = new
        {
            status = "healthy",
            timestamp = DateTime.UtcNow,
            version = "1.0.0",
            checks = new Dictionary<string, object>()
        };

        // Test MrWho API connectivity
        try
        {
            var result = await _realmsApiService.GetRealmsAsync(page: 1, pageSize: 1);
            healthStatus.checks["mrwho_api"] = new
            {
                status = result != null ? "healthy" : "unhealthy",
                message = result != null ? "API connectivity successful" : "API returned null",
                timestamp = DateTime.UtcNow
            };
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Health check failed for MrWho API");
            healthStatus.checks["mrwho_api"] = new
            {
                status = "unhealthy",
                message = ex.Message,
                exception = ex.GetType().Name,
                timestamp = DateTime.UtcNow
            };
        }

        // Test authentication status
        try
        {
            var isAuthenticated = HttpContext.User.Identity?.IsAuthenticated == true;
            var userName = HttpContext.User.Identity?.Name;
            
            healthStatus.checks["authentication"] = new
            {
                status = isAuthenticated ? "healthy" : "unauthenticated",
                message = isAuthenticated ? $"User {userName} is authenticated" : "User is not authenticated",
                timestamp = DateTime.UtcNow
            };
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Health check failed for authentication");
            healthStatus.checks["authentication"] = new
            {
                status = "error",
                message = ex.Message,
                exception = ex.GetType().Name,
                timestamp = DateTime.UtcNow
            };
        }

        return Ok(healthStatus);
    }
}