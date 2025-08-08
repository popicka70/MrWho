using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Options;
using OpenIddict.Validation.AspNetCore;

namespace MrWho.Services;

/// <summary>
/// Dynamic authorization policy provider that loads client-specific authentication schemes from database at runtime
/// This solves the chicken-and-egg problem of needing database access during service registration
/// </summary>
public class DynamicAuthorizationPolicyProvider : IAuthorizationPolicyProvider
{
    private readonly DefaultAuthorizationPolicyProvider _fallbackPolicyProvider;
    private readonly IServiceScopeFactory _serviceScopeFactory;
    private readonly ILogger<DynamicAuthorizationPolicyProvider> _logger;
    private AuthorizationPolicy? _defaultPolicy;
    private readonly SemaphoreSlim _policyCreationSemaphore = new(1, 1);

    public DynamicAuthorizationPolicyProvider(
        IOptions<AuthorizationOptions> options,
        IServiceScopeFactory serviceScopeFactory,
        ILogger<DynamicAuthorizationPolicyProvider> logger)
    {
        _fallbackPolicyProvider = new DefaultAuthorizationPolicyProvider(options);
        _serviceScopeFactory = serviceScopeFactory;
        _logger = logger;
    }

    public async Task<AuthorizationPolicy> GetDefaultPolicyAsync()
    {
        if (_defaultPolicy != null)
        {
            return _defaultPolicy;
        }

        await _policyCreationSemaphore.WaitAsync();
        try
        {
            if (_defaultPolicy != null)
            {
                return _defaultPolicy;
            }

            _logger.LogInformation("?? Creating dynamic default authorization policy with database-loaded client schemes");

            // Load all client schemes from database
            var allSchemes = await GetAllAuthenticationSchemesAsync();

            _logger.LogInformation("? Loaded {SchemeCount} authentication schemes for default policy", allSchemes.Count);

            _defaultPolicy = new AuthorizationPolicyBuilder()
                .RequireAuthenticatedUser()
                .AddAuthenticationSchemes(allSchemes.ToArray())
                .Build();

            return _defaultPolicy;
        }
        finally
        {
            _policyCreationSemaphore.Release();
        }
    }

    public async Task<AuthorizationPolicy?> GetPolicyAsync(string policyName)
    {
        // Handle special policies first
        switch (policyName)
        {
            case "UserInfoPolicy":
                return new AuthorizationPolicyBuilder()
                    .RequireAuthenticatedUser()
                    .AddAuthenticationSchemes(OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme)
                    .Build();

            case "AdminOnly":
                return new AuthorizationPolicyBuilder()
                    .RequireAuthenticatedUser()
                    .AddAuthenticationSchemes("Identity.Application.mrwho_admin_web")
                    .Build();

            case "DemoAccess":
                return new AuthorizationPolicyBuilder()
                    .RequireAuthenticatedUser()
                    .AddAuthenticationSchemes("Identity.Application.mrwho_demo1")
                    .Build();

            case "ApiAccess":
                return new AuthorizationPolicyBuilder()
                    .RequireAuthenticatedUser()
                    .AddAuthenticationSchemes("Identity.Application.postman_client", 
                                            OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme)
                    .Build();
        }

        // Check if this is a dynamic client policy request
        if (policyName.StartsWith("Client_"))
        {
            var clientId = policyName.Replace("Client_", "");
            var schemeName = $"Identity.Application.{clientId}";
            
            _logger.LogDebug("?? Creating dynamic policy for client: {ClientId} (Scheme: {SchemeName})", clientId, schemeName);
            
            return new AuthorizationPolicyBuilder()
                .RequireAuthenticatedUser()
                .AddAuthenticationSchemes(schemeName)
                .Build();
        }

        // Fall back to default provider for unknown policies
        return await _fallbackPolicyProvider.GetPolicyAsync(policyName);
    }

    public Task<AuthorizationPolicy> GetFallbackPolicyAsync()
    {
        return _fallbackPolicyProvider.GetFallbackPolicyAsync();
    }

    private async Task<List<string>> GetAllAuthenticationSchemesAsync()
    {
        var schemes = new List<string>
        {
            // Base schemes that are always available
            "Identity.Application",
            OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme
        };

        try
        {
            using var scope = _serviceScopeFactory.CreateScope();
            var oidcClientService = scope.ServiceProvider.GetRequiredService<IOidcClientService>();

            // Load all enabled clients from database
            var enabledClients = await oidcClientService.GetEnabledClientsAsync();

            foreach (var client in enabledClients)
            {
                var schemeName = $"Identity.Application.{client.ClientId}";
                schemes.Add(schemeName);
                
                _logger.LogDebug("?? Added dynamic scheme to default policy: {SchemeName} (Client: {ClientId})", 
                    schemeName, client.ClientId);
            }

            _logger.LogInformation("?? Dynamic authorization policy configured with {TotalSchemes} authentication schemes ({DynamicSchemes} from database)", 
                schemes.Count, enabledClients.Count());
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "? Failed to load client schemes from database, using static schemes only");
            
            // Fallback to essential static schemes if database access fails
            schemes.AddRange(new[]
            {
                "Identity.Application.mrwho_admin_web",
                "Identity.Application.mrwho_demo1",
                "Identity.Application.postman_client"
            });
        }

        return schemes;
    }
}