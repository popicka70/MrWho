using Microsoft.AspNetCore.Http;
using MrWhoAdmin.Web.Controllers;

namespace MrWhoAdmin.Web.Services;

/// <summary>
/// Direct health service that calls controller methods without HTTP
/// </summary>
public interface IDirectHealthService
{
    /// <summary>
    /// Gets basic health status directly
    /// </summary>
    Task<HealthStatus?> GetBasicHealthAsync();

    /// <summary>
    /// Gets detailed health status directly
    /// </summary>
    Task<DetailedHealthStatus?> GetDetailedHealthAsync();

    /// <summary>
    /// Gets liveness status directly
    /// </summary>
    Task<LivenessStatus?> GetLivenessAsync();

    /// <summary>
    /// Gets readiness status directly
    /// </summary>
    Task<ReadinessStatus?> GetReadinessAsync();

    /// <summary>
    /// Gets authentication schemes info directly
    /// </summary>
    Task<AuthSchemesInfo?> GetAuthSchemesAsync();
}

/// <summary>
/// Direct health service implementation
/// </summary>
public class DirectHealthService : IDirectHealthService
{
    private readonly IServiceProvider _serviceProvider;
    private readonly ILogger<DirectHealthService> _logger;
    private readonly IHttpContextAccessor _httpContextAccessor;

    public DirectHealthService(
        IServiceProvider serviceProvider,
        ILogger<DirectHealthService> logger,
        IHttpContextAccessor httpContextAccessor)
    {
        _serviceProvider = serviceProvider;
        _logger = logger;
        _httpContextAccessor = httpContextAccessor;
    }

    public Task<HealthStatus?> GetBasicHealthAsync()
    {
        try
        {
            using var scope = _serviceProvider.CreateScope();
            var controller = scope.ServiceProvider.GetRequiredService<HealthController>();

            var result = controller.Get();
            if (result is Microsoft.AspNetCore.Mvc.OkObjectResult okResult && okResult.Value != null)
            {
                return Task.FromResult(ConvertToHealthStatus(okResult.Value));
            }

            return Task.FromResult<HealthStatus?>(null);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting basic health directly");
            return Task.FromResult<HealthStatus?>(null);
        }
    }

    public async Task<DetailedHealthStatus?> GetDetailedHealthAsync()
    {
        try
        {
            using var scope = _serviceProvider.CreateScope();
            var controller = scope.ServiceProvider.GetRequiredService<HealthController>();

            // Set HttpContext for authentication-dependent methods
            if (_httpContextAccessor.HttpContext != null)
            {
                controller.ControllerContext = new Microsoft.AspNetCore.Mvc.ControllerContext
                {
                    HttpContext = _httpContextAccessor.HttpContext
                };
            }

            var result = await controller.GetDetailed();
            if (result is Microsoft.AspNetCore.Mvc.OkObjectResult okResult && okResult.Value != null)
            {
                return ConvertToDetailedHealthStatus(okResult.Value);
            }

            return null;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting detailed health directly");
            return null;
        }
    }

    public Task<LivenessStatus?> GetLivenessAsync()
    {
        try
        {
            using var scope = _serviceProvider.CreateScope();
            var controller = scope.ServiceProvider.GetRequiredService<HealthController>();

            var result = controller.GetLiveness();
            if (result is Microsoft.AspNetCore.Mvc.OkObjectResult okResult && okResult.Value != null)
            {
                return Task.FromResult(ConvertToLivenessStatus(okResult.Value));
            }

            return Task.FromResult<LivenessStatus?>(null);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting liveness directly");
            return Task.FromResult<LivenessStatus?>(null);
        }
    }

    public async Task<ReadinessStatus?> GetReadinessAsync()
    {
        try
        {
            using var scope = _serviceProvider.CreateScope();
            var controller = scope.ServiceProvider.GetRequiredService<HealthController>();

            var result = await controller.GetReadiness();
            if (result is Microsoft.AspNetCore.Mvc.OkObjectResult okResult && okResult.Value != null)
            {
                return ConvertToReadinessStatus(okResult.Value);
            }

            return null;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting readiness directly");
            return null;
        }
    }

    public Task<AuthSchemesInfo?> GetAuthSchemesAsync()
    {
        try
        {
            using var scope = _serviceProvider.CreateScope();
            var controller = scope.ServiceProvider.GetRequiredService<HealthController>();

            // Set HttpContext for authentication-dependent methods
            if (_httpContextAccessor.HttpContext != null)
            {
                controller.ControllerContext = new Microsoft.AspNetCore.Mvc.ControllerContext
                {
                    HttpContext = _httpContextAccessor.HttpContext
                };
            }
            else
            {
                // If no HttpContext available, return a placeholder response
                _logger.LogWarning("No HttpContext available for authentication schemes check");
                return Task.FromResult<AuthSchemesInfo?>(new AuthSchemesInfo
                {
                    Timestamp = DateTime.UtcNow,
                    Application = "MrWho Admin Web",
                    User = new UserInfo
                    {
                        IsAuthenticated = false,
                        Name = "N/A - No HttpContext",
                        AuthenticationType = "N/A",
                        ClaimsCount = 0
                    },
                    Cookies = new List<CookieInfo>(),
                    Schemes = new SchemeInfo
                    {
                        DefaultScheme = "AdminCookies",
                        ChallengeScheme = "AdminOIDC",
                        Note = "Admin app uses client-specific schemes for session isolation"
                    }
                });
            }

            var result = controller.GetAuthenticationSchemes();
            if (result is Microsoft.AspNetCore.Mvc.OkObjectResult okResult && okResult.Value != null)
            {
                return Task.FromResult(ConvertToAuthSchemesInfo(okResult.Value));
            }

            return Task.FromResult<AuthSchemesInfo?>(null);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting auth schemes directly");
            return Task.FromResult<AuthSchemesInfo?>(null);
        }
    }

    private HealthStatus? ConvertToHealthStatus(object value)
    {
        var json = System.Text.Json.JsonSerializer.Serialize(value);
        return System.Text.Json.JsonSerializer.Deserialize<HealthStatus>(json, new System.Text.Json.JsonSerializerOptions
        {
            PropertyNameCaseInsensitive = true
        });
    }

    private DetailedHealthStatus? ConvertToDetailedHealthStatus(object value)
    {
        var json = System.Text.Json.JsonSerializer.Serialize(value);
        return System.Text.Json.JsonSerializer.Deserialize<DetailedHealthStatus>(json, new System.Text.Json.JsonSerializerOptions
        {
            PropertyNameCaseInsensitive = true
        });
    }

    private LivenessStatus? ConvertToLivenessStatus(object value)
    {
        var json = System.Text.Json.JsonSerializer.Serialize(value);
        return System.Text.Json.JsonSerializer.Deserialize<LivenessStatus>(json, new System.Text.Json.JsonSerializerOptions
        {
            PropertyNameCaseInsensitive = true
        });
    }

    private ReadinessStatus? ConvertToReadinessStatus(object value)
    {
        var json = System.Text.Json.JsonSerializer.Serialize(value);
        return System.Text.Json.JsonSerializer.Deserialize<ReadinessStatus>(json, new System.Text.Json.JsonSerializerOptions
        {
            PropertyNameCaseInsensitive = true
        });
    }

    private AuthSchemesInfo? ConvertToAuthSchemesInfo(object value)
    {
        var json = System.Text.Json.JsonSerializer.Serialize(value);
        return System.Text.Json.JsonSerializer.Deserialize<AuthSchemesInfo>(json, new System.Text.Json.JsonSerializerOptions
        {
            PropertyNameCaseInsensitive = true
        });
    }
}
