using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Options;
using OpenIddict.Validation.AspNetCore;
using System.Security.Claims;
using MrWho.Shared;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;

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

            _logger.LogInformation("Creating dynamic default authorization policy (loading client schemes)");

            var allSchemes = await GetAllAuthenticationSchemesAsync();
            _logger.LogInformation("Loaded {SchemeCount} authentication schemes for default policy", allSchemes.Count);

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
                    .AddAuthenticationSchemes("Identity.Application.postman_client", OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme)
                    .Build();
            case AuthorizationPolicies.AdminClientApi:
                return new AuthorizationPolicyBuilder()
                    .RequireAuthenticatedUser()
                    .AddAuthenticationSchemes(OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme)
                    .RequireAssertion(ctx =>
                    {
                        var user = ctx.User;
                        if (user?.Identity?.IsAuthenticated != true) return false;
                        bool hasMrWhoUse = user.FindAll("scope")
                            .Any(c => c.Value.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                                              .Contains(StandardScopes.MrWhoUse));
                        if (!hasMrWhoUse) return false;
                        string adminClientId = MrWhoConstants.AdminClientId;
                        bool isAdminClient = user.HasClaim(c => (c.Type == "azp" || c.Type == "client_id") && c.Value == adminClientId);
                        return isAdminClient;
                    })
                    .Build();
        }

        if (policyName.StartsWith("Client_", StringComparison.Ordinal))
        {
            var clientId = policyName[7..];
            var schemeName = $"Identity.Application.{clientId}";
            _logger.LogDebug("Creating dynamic client policy for {ClientId} (Scheme {SchemeName})", clientId, schemeName);
            return new AuthorizationPolicyBuilder()
                .RequireAuthenticatedUser()
                .AddAuthenticationSchemes(schemeName)
                .Build();
        }

        return await _fallbackPolicyProvider.GetPolicyAsync(policyName);
    }

    public Task<AuthorizationPolicy?> GetFallbackPolicyAsync() => _fallbackPolicyProvider.GetFallbackPolicyAsync();

    private async Task<List<string>> GetAllAuthenticationSchemesAsync()
    {
        var schemes = new List<string>
        {
            // Always include base identity app scheme (default) and token validation scheme
            "Identity.Application",
            OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme
        };

        try
        {
            using var scope = _serviceScopeFactory.CreateScope();
            var oidcClientService = scope.ServiceProvider.GetRequiredService<IOidcClientService>();
            var schemeProvider = scope.ServiceProvider.GetRequiredService<IAuthenticationSchemeProvider>();
            var cookieOptionsMonitor = scope.ServiceProvider.GetRequiredService<IOptionsMonitor<CookieAuthenticationOptions>>();

            var enabledClients = await oidcClientService.GetEnabledClientsAsync();
            foreach (var client in enabledClients)
            {
                var schemeName = $"Identity.Application.{client.ClientId}";

                // Only include scheme if registered
                var registered = await schemeProvider.GetSchemeAsync(schemeName);
                if (registered == null)
                {
                    _logger.LogDebug("Skipping scheme {SchemeName} (not yet registered)", schemeName);
                    continue;
                }

                // Ensure cookie options exist & have a cookie name to avoid CookieAuthenticationHandler NRE
                try
                {
                    var opts = cookieOptionsMonitor.Get(schemeName);
                    if (string.IsNullOrWhiteSpace(opts.Cookie?.Name))
                    {
                        _logger.LogWarning("Skipping scheme {SchemeName} due to missing cookie name", schemeName);
                        continue;
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Skipping scheme {SchemeName}; unable to resolve CookieAuthenticationOptions", schemeName);
                    continue;
                }

                schemes.Add(schemeName);
                _logger.LogDebug("Added dynamic scheme to default policy: {SchemeName}", schemeName);
            }

            _logger.LogInformation("Dynamic authorization policy configured with {Total} schemes ({Dynamic} dynamic)", schemes.Count, schemes.Count - 2);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed loading dynamic schemes; using static only");
            // Fallback essential static scheme of admin
            schemes.Add("Identity.Application.mrwho_admin_web");
        }

        return schemes.Distinct().ToList();
    }
}