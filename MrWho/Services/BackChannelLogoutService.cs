using Microsoft.AspNetCore.Authentication;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using MrWho.Data;

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
    private readonly ApplicationDbContext _context;

    public BackChannelLogoutService(
        IHttpClientFactory httpClientFactory,
        ILogger<BackChannelLogoutService> logger,
        ApplicationDbContext context)
    {
        _httpClientFactory = httpClientFactory;
        _logger = logger;
        _context = context;
    }

    public async Task NotifyClientLogoutAsync(string authorizationId, string subject, string sessionId)
    {
        try
        {
            // Find all clients that might have sessions for this user
            var clientsToNotify = await GetClientsForLogoutNotificationAsync(subject);

            var tasks = clientsToNotify.Select(client => 
                NotifyClientLogoutAsync(client.ClientId, subject, sessionId));

            await Task.WhenAll(tasks);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error sending back-channel logout notifications for authorization {AuthorizationId}", authorizationId);
        }
    }

    public async Task NotifyClientLogoutAsync(string clientId, string subject, string sessionId, string? logoutToken = null)
    {
        try
        {
            var client = await _context.Clients
                .FirstOrDefaultAsync(c => c.ClientId == clientId);

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

    public async Task<string> CreateLogoutTokenAsync(string clientId, string subject, string sessionId)
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

        return JsonSerializer.Serialize(logoutToken);
    }

    private async Task<List<Models.Client>> GetClientsForLogoutNotificationAsync(string subject)
    {
        // Get all clients that support back-channel logout
        return await _context.Clients
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