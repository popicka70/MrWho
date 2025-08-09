using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Options;
using OpenIddict.Validation.AspNetCore;

namespace MrWho.Services;

/// <summary>
/// SINGLE SOURCE OF TRUTH for all authorization policies in the application
/// 
/// This provider dynamically loads client-specific authentication schemes from database at runtime
/// and centralizes ALL authorization policy configuration in one place. It solves the chicken-and-egg 
/// problem of needing database access during service registration.
/// 
/// Handles:
/// - Static Security Policies: UserInfoPolicy (OpenIddict validation only)
/// - Static Client Policies: AdminOnly, DemoAccess, ApiAccess  
/// - Dynamic Default Policy: Loads ALL client schemes from database automatically
/// - Dynamic Client Policies: Client_{clientId} format for any database client
/// - Fallback: Uses DefaultAuthorizationPolicyProvider for unknown policies
/// 
/// Benefits:
/// ? Single location for all authorization configuration
/// ? Database-driven policies that update automatically when clients are added
/// ? No code changes needed for new clients
/// ? Proper fallback handling when database is unavailable
/// ? Thread-safe policy creation with caching
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
        // ====================================================================
        // CENTRALIZED STATIC POLICY CONFIGURATION
        // All static authorization policies are defined here in one place
        // ====================================================================
        
        switch (policyName)
        {
            case "UserInfoPolicy":
                // SECURITY: UserInfo endpoint must only use OpenIddict validation (no cookie auth)
                return new AuthorizationPolicyBuilder()
                    .RequireAuthenticatedUser()
                    .AddAuthenticationSchemes(OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme)
                    .Build();

            case "AdminOnly":
                // Admin-only access using the admin web client cookie authentication
                return new AuthorizationPolicyBuilder()
                    .RequireAuthenticatedUser()
                    .AddAuthenticationSchemes("Identity.Application.mrwho_admin_web")
                    .Build();

            case "DemoAccess":
                // Demo client access using the demo client cookie authentication
                return new AuthorizationPolicyBuilder()
                    .RequireAuthenticatedUser()
                    .AddAuthenticationSchemes("Identity.Application.mrwho_demo1")
                    .Build();

            case "ApiAccess":
                // API access supporting both Postman client cookies and OpenIddict token validation
                return new AuthorizationPolicyBuilder()
                    .RequireAuthenticatedUser()
                    .AddAuthenticationSchemes("Identity.Application.postman_client", 
                                            OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme)
                    .Build();
        }

        // ====================================================================
        // DYNAMIC CLIENT POLICY CONFIGURATION  
        // Format: "Client_{clientId}" - automatically creates policies for any database client
        // ====================================================================
        
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

        // ====================================================================
        // FALLBACK TO DEFAULT PROVIDER
        // ====================================================================
        
        // Fall back to default provider for unknown policies
        return await _fallbackPolicyProvider.GetPolicyAsync(policyName);
    }

    public Task<AuthorizationPolicy> GetFallbackPolicyAsync()
    {
        return _fallbackPolicyProvider.GetFallbackPolicyAsync()!;
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

        schemes = schemes.Distinct().ToList();

        return schemes;
    }
}