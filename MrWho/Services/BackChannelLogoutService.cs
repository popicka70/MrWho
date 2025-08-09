using Microsoft.AspNetCore.Authentication;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using MrWho.Data;
using OpenIddict.Abstractions;

namespace MrWho.Services;

/// <summary>
/// Service for handling back-channel logout notifications to client applications
/// </summary>
public interface IBackChannelLogoutService
{
    /// <summary>
    /// Sends back-channel logout notifications to all clients for a user session
    /// </summary>
    Task NotifyClientLogoutAsync(string authorizationId, string subject, string sessionId);

    /// <summary>
    /// Sends back-channel logout notification to a specific client
    /// </summary>
    Task NotifyClientLogoutAsync(string clientId, string subject, string sessionId, string? logoutToken = null);

    /// <summary>
    /// Creates a logout token for back-channel logout
    /// </summary>
    Task<string> CreateLogoutTokenAsync(string clientId, string subject, string sessionId);
}

public class BackChannelLogoutService : IBackChannelLogoutService
{
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly ILogger<BackChannelLogoutService> _logger;
    private readonly IServiceProvider _serviceProvider; // Changed from direct DbContext injection

    public BackChannelLogoutService(
        IHttpClientFactory httpClientFactory,
        ILogger<BackChannelLogoutService> logger,
        IServiceProvider serviceProvider) // Use service provider to create scoped contexts
    {
        _httpClientFactory = httpClientFactory;
        _logger = logger;
        _serviceProvider = serviceProvider;
    }

    public async Task NotifyClientLogoutAsync(string authorizationId, string subject, string sessionId)
    {
        try
        {
            // Get the specific client for this authorization
            Models.Client? clientToNotify;
            using (var scope = _serviceProvider.CreateScope())
            {
                var context = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
                var authorizationManager = scope.ServiceProvider.GetRequiredService<IOpenIddictAuthorizationManager>();
                var applicationManager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
                
                // Find the authorization and get its application
                var authorization = await authorizationManager.FindByIdAsync(authorizationId);
                if (authorization == null)
                {
                    _logger.LogWarning("Authorization {AuthorizationId} not found for logout notification", authorizationId);
                    return;
                }
                
                var applicationId = await authorizationManager.GetApplicationIdAsync(authorization);
                if (string.IsNullOrEmpty(applicationId))
                {
                    _logger.LogWarning("Authorization {AuthorizationId} has no associated application", authorizationId);
                    return;
                }
                
                var application = await applicationManager.FindByIdAsync(applicationId);
                if (application == null)
                {
                    _logger.LogWarning("Application {ApplicationId} not found for authorization {AuthorizationId}", applicationId, authorizationId);
                    return;
                }
                
                var clientId = await applicationManager.GetClientIdAsync(application);
                if (string.IsNullOrEmpty(clientId))
                {
                    _logger.LogWarning("Application {ApplicationId} has no client ID", applicationId);
                    return;
                }
                
                // Get the client from our database if it exists
                clientToNotify = await context.Clients
                    .FirstOrDefaultAsync(c => c.ClientId == clientId);
                
                // If not in our database, create a temporary client object for notification
                if (clientToNotify == null)
                {
                    clientToNotify = new Models.Client
                    {
                        ClientId = clientId,
                        IsEnabled = true // Assume enabled for OpenIddict clients
                    };
                }
            }

            // Send notification to the specific client
            await NotifyClientLogoutInternalAsync(clientToNotify.ClientId, subject, sessionId);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error sending back-channel logout notifications for authorization {AuthorizationId}", authorizationId);
        }
    }

    public async Task NotifyClientLogoutAsync(string clientId, string subject, string sessionId, string? logoutToken = null)
    {
        await NotifyClientLogoutInternalAsync(clientId, subject, sessionId, logoutToken);
    }

    /// <summary>
    /// Internal method that creates its own DbContext scope for thread safety
    /// </summary>
    private async Task NotifyClientLogoutInternalAsync(string clientId, string subject, string sessionId, string? logoutToken = null)
    {
        try
        {
            Models.Client? client;
            
            // Create a new scope and context for this operation
            using (var scope = _serviceProvider.CreateScope())
            {
                var context = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
                client = await context.Clients
                    .FirstOrDefaultAsync(c => c.ClientId == clientId);
            }

            if (client == null)
            {
                _logger.LogWarning("Client {ClientId} not found for logout notification", clientId);
                return;
            }

            // Get the back-channel logout URI for this client
            var logoutUri = GetBackChannelLogoutUri(client);
            if (string.IsNullOrEmpty(logoutUri))
            {
                _logger.LogDebug("No back-channel logout URI configured for client {ClientId}", clientId);
                return;
            }

            // Create logout token if not provided
            if (string.IsNullOrEmpty(logoutToken))
            {
                logoutToken = await CreateLogoutTokenAsync(clientId, subject, sessionId);
            }

            // Send the logout notification
            using var httpClient = _httpClientFactory.CreateClient();
            httpClient.Timeout = TimeSpan.FromSeconds(10); // Quick timeout for logout notifications

            var formData = new FormUrlEncodedContent(new[]
            {
                new KeyValuePair<string, string>("logout_token", logoutToken)
            });

            var response = await httpClient.PostAsync(logoutUri, formData);

            if (response.IsSuccessStatusCode)
            {
                _logger.LogInformation("Back-channel logout notification sent successfully to client {ClientId}", clientId);
            }
            else
            {
                _logger.LogWarning("Back-channel logout notification failed for client {ClientId} with status {StatusCode}", 
                    clientId, response.StatusCode);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error sending back-channel logout notification to client {ClientId}", clientId);
        }
    }

    public Task<string> CreateLogoutTokenAsync(string clientId, string subject, string sessionId)
    {
        // For now, create a simple JWT-like structure
        // In production, this should be a properly signed JWT
        var logoutToken = new
        {
            iss = "https://localhost:7113", // Your OIDC server
            sub = subject,
            aud = clientId,
            iat = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            jti = Guid.NewGuid().ToString(),
            events = new Dictionary<string, object>
            {
                ["http://schemas.openid.net/event/backchannel-logout"] = new { }
            },
            sid = sessionId
        };

    return Task.FromResult(JsonSerializer.Serialize(logoutToken));
    }

    /// <summary>
    /// Gets clients for logout notification using the provided context
    /// </summary>
    private async Task<List<Models.Client>> GetClientsForLogoutNotificationAsync(ApplicationDbContext context, string subject)
    {
        // Get all clients that support back-channel logout
        return await context.Clients
            .Where(c => c.IsEnabled)
            .ToListAsync();
    }

    private string? GetBackChannelLogoutUri(Models.Client client)
    {
        // For now, construct a standard back-channel logout URI
        // In a real implementation, this would be stored in the client configuration
        return client.ClientId switch
        {
            "mrwho_demo1" => "https://localhost:7037/signout-backchannel",
            "mrwho_admin_web" => "https://localhost:7257/signout-backchannel",
            _ => null
        };
    }
}