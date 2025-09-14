using System.Diagnostics;
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
    private readonly IServiceProvider _serviceProvider;

    public HealthController(
        IRealmsApiService realmsApiService,
        ILogger<HealthController> logger,
        IServiceProvider serviceProvider)
    {
        _realmsApiService = realmsApiService;
        _logger = logger;
        _serviceProvider = serviceProvider;
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
            version = "1.0.0",
            application = "MrWho Admin Web"
        });
    }

    /// <summary>
    /// Health check with MrWho API connectivity test
    /// </summary>
    [HttpGet("detailed")]
    [Authorize]
    public async Task<IActionResult> GetDetailed()
    {
        var stopwatch = Stopwatch.StartNew();
        var healthStatus = new
        {
            status = "healthy",
            timestamp = DateTime.UtcNow,
            version = "1.0.0",
            application = "MrWho Admin Web",
            checks = new Dictionary<string, object>(),
            environment = new
            {
                machineName = Environment.MachineName,
                osVersion = Environment.OSVersion.ToString(),
                processorCount = Environment.ProcessorCount,
                workingSet = Environment.WorkingSet,
                managedMemory = GC.GetTotalMemory(false)
            }
        };

        // Test MrWho API connectivity
        await TestMrWhoApiConnectivity(healthStatus.checks);

        // Test authentication status
        await TestAuthenticationStatus(healthStatus.checks);

        // Test API services concurrency
        await TestConcurrencyHandling(healthStatus.checks);

        stopwatch.Stop();
        healthStatus.checks["total_check_time"] = new
        {
            status = "info",
            message = $"Health checks completed in {stopwatch.ElapsedMilliseconds}ms",
            elapsed_ms = stopwatch.ElapsedMilliseconds,
            timestamp = DateTime.UtcNow
        };

        // Determine overall health
        var hasUnhealthy = healthStatus.checks.Values
            .Cast<dynamic>()
            .Any(check => check.status == "unhealthy" || check.status == "error");

        if (hasUnhealthy)
        {
            return StatusCode(503, healthStatus); // Service Unavailable
        }

        return Ok(healthStatus);
    }

    /// <summary>
    /// Lightweight health check for load balancer probes
    /// </summary>
    [HttpGet("liveness")]
    public IActionResult GetLiveness()
    {
        return Ok(new
        {
            status = "alive",
            timestamp = DateTime.UtcNow
        });
    }

    /// <summary>
    /// Readiness check for service dependencies
    /// </summary>
    [HttpGet("readiness")]
    public async Task<IActionResult> GetReadiness()
    {
        try
        {
            // Quick API connectivity check
            var result = await _realmsApiService.GetRealmsAsync(page: 1, pageSize: 1);

            return Ok(new
            {
                status = result != null ? "ready" : "not_ready",
                timestamp = DateTime.UtcNow
            });
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Readiness check failed");
            return StatusCode(503, new
            {
                status = "not_ready",
                error = ex.Message,
                timestamp = DateTime.UtcNow
            });
        }
    }

    /// <summary>
    /// Diagnostic endpoint to check authentication schemes and session isolation
    /// </summary>
    [HttpGet("auth-schemes")]
    [Authorize]
    public IActionResult GetAuthenticationSchemes()
    {
        try
        {
            var result = new
            {
                timestamp = DateTime.UtcNow,
                application = "MrWho Admin Web",
                user = new
                {
                    isAuthenticated = HttpContext.User.Identity?.IsAuthenticated == true,
                    name = HttpContext.User.Identity?.Name,
                    authenticationType = HttpContext.User.Identity?.AuthenticationType,
                    claimsCount = HttpContext.User.Claims.Count()
                },
                cookies = HttpContext.Request.Cookies
                    .Where(c => c.Key.Contains("MrWho") || c.Key.Contains("AspNet"))
                    .Select(c => new { name = c.Key, length = c.Value.Length })
                    .ToList(),
                schemes = new
                {
                    defaultScheme = "AdminCookies",
                    challengeScheme = "AdminOIDC",
                    note = "Admin app uses client-specific schemes for session isolation"
                }
            };

            return Ok(result);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting authentication schemes info");
            return StatusCode(500, new { error = ex.Message });
        }
    }

    private async Task TestMrWhoApiConnectivity(Dictionary<string, object> checks)
    {
        try
        {
            var stopwatch = Stopwatch.StartNew();
            var result = await _realmsApiService.GetRealmsAsync(page: 1, pageSize: 1);
            stopwatch.Stop();

            checks["mrwho_api"] = new
            {
                status = result != null ? "healthy" : "unhealthy",
                message = result != null ? "API connectivity successful" : "API returned null",
                response_time_ms = stopwatch.ElapsedMilliseconds,
                timestamp = DateTime.UtcNow
            };
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Health check failed for MrWho API");
            checks["mrwho_api"] = new
            {
                status = "unhealthy",
                message = ex.Message,
                exception = ex.GetType().Name,
                timestamp = DateTime.UtcNow
            };
        }
    }

    private Task TestAuthenticationStatus(Dictionary<string, object> checks)
    {
        try
        {
            var isAuthenticated = HttpContext.User.Identity?.IsAuthenticated == true;
            var userName = HttpContext.User.Identity?.Name;
            var authType = HttpContext.User.Identity?.AuthenticationType;
            var claimsCount = HttpContext.User.Claims.Count();

            checks["authentication"] = new
            {
                status = isAuthenticated ? "healthy" : "unauthenticated",
                message = isAuthenticated ? $"User {userName} is authenticated" : "User is not authenticated",
                authentication_type = authType,
                claims_count = claimsCount,
                timestamp = DateTime.UtcNow
            };
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Health check failed for authentication");
            checks["authentication"] = new
            {
                status = "error",
                message = ex.Message,
                exception = ex.GetType().Name,
                timestamp = DateTime.UtcNow
            };
        }

        return Task.CompletedTask;
    }

    private async Task TestConcurrencyHandling(Dictionary<string, object> checks)
    {
        try
        {
            var stopwatch = Stopwatch.StartNew();

            // Test concurrent API service operations (tests HTTP client handling)
            var tasks = Enumerable.Range(1, 3).Select(async i =>
            {
                try
                {
                    var result = await _realmsApiService.GetRealmsAsync(page: 1, pageSize: 1);
                    return result != null;
                }
                catch
                {
                    return false;
                }
            });

            var results = await Task.WhenAll(tasks);
            stopwatch.Stop();

            var allSuccessful = results.All(r => r);

            checks["concurrency"] = new
            {
                status = allSuccessful ? "healthy" : "warning",
                message = allSuccessful ? "Concurrent operations successful" : "Some concurrent operations failed",
                concurrent_operations = results.Length,
                successful_operations = results.Count(r => r),
                test_time_ms = stopwatch.ElapsedMilliseconds,
                timestamp = DateTime.UtcNow
            };
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Health check failed for concurrency handling");
            checks["concurrency"] = new
            {
                status = "error",
                message = ex.Message,
                exception = ex.GetType().Name,
                timestamp = DateTime.UtcNow
            };
        }
    }
}
