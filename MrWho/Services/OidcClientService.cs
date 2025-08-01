using Microsoft.EntityFrameworkCore;
using OpenIddict.Abstractions;
using MrWho.Data;
using MrWho.Models;

namespace MrWho.Services;

/// <summary>
/// Service for managing dynamic OIDC client configurations
/// </summary>
public interface IOidcClientService
{
    Task InitializeDefaultRealmAndClientsAsync();
    Task<IEnumerable<Client>> GetEnabledClientsAsync();
    Task SyncClientWithOpenIddictAsync(Client client);
}

public class OidcClientService : IOidcClientService
{
    private readonly ApplicationDbContext _context;
    private readonly IOpenIddictApplicationManager _applicationManager;
    private readonly ILogger<OidcClientService> _logger;

    public OidcClientService(
        ApplicationDbContext context,
        IOpenIddictApplicationManager applicationManager,
        ILogger<OidcClientService> logger)
    {
        _context = context;
        _applicationManager = applicationManager;
        _logger = logger;
    }

    public async Task InitializeDefaultRealmAndClientsAsync()
    {
        // Create default realm if it doesn't exist
        var defaultRealm = await _context.Realms.FirstOrDefaultAsync(r => r.Name == "default");
        if (defaultRealm == null)
        {
            defaultRealm = new Realm
            {
                Name = "default",
                DisplayName = "Default Realm",
                Description = "Default realm for OIDC clients",
                IsEnabled = true
            };
            _context.Realms.Add(defaultRealm);
            await _context.SaveChangesAsync();
            _logger.LogInformation("Created default realm");
        }

        // Create default client if it doesn't exist
        var defaultClient = await _context.Clients
            .Include(c => c.RedirectUris)
            .Include(c => c.PostLogoutUris)
            .Include(c => c.Scopes)  
            .Include(c => c.Permissions)
            .FirstOrDefaultAsync(c => c.ClientId == "postman_client");

        if (defaultClient == null)
        {
            defaultClient = new Client
            {
                ClientId = "postman_client",
                ClientSecret = "postman_secret",
                Name = "Postman Test Client",
                Description = "Default test client for development",
                RealmId = defaultRealm.Id,
                IsEnabled = true,
                ClientType = ClientType.Confidential,
                AllowAuthorizationCodeFlow = true,
                AllowClientCredentialsFlow = true,
                AllowPasswordFlow = true,
                AllowRefreshTokenFlow = true,
                RequirePkce = false,
                RequireClientSecret = true
            };

            _context.Clients.Add(defaultClient);
            await _context.SaveChangesAsync();

            // Add redirect URIs
            var redirectUris = new[]
            {
                "https://localhost:7001/callback",
                "http://localhost:5001/callback",
                "https://localhost:7002/",
                "https://localhost:7002/callback",
                "https://localhost:7002/signin-oidc",
                "https://localhost:7257/",
                "https://localhost:7257/callback",
                "https://localhost:7257/signin-oidc"
            };

            foreach (var uri in redirectUris)
            {
                _context.ClientRedirectUris.Add(new ClientRedirectUri
                {
                    ClientId = defaultClient.Id,
                    Uri = uri
                });
            }

            // Add post-logout URIs
            var postLogoutUris = new[]
            {
                "https://localhost:7001/",
                "http://localhost:5001/",
                "https://localhost:7002/",
                "https://localhost:7002/signout-callback-oidc",
                "https://localhost:7257/",
                "https://localhost:7257/signout-callback-oidc"
            };

            foreach (var uri in postLogoutUris)
            {
                _context.ClientPostLogoutUris.Add(new ClientPostLogoutUri
                {
                    ClientId = defaultClient.Id,
                    Uri = uri
                });
            }

            // Add scopes
            var scopes = new[] { "openid", "email", "profile", "roles" };
            foreach (var scope in scopes)
            {
                _context.ClientScopes.Add(new ClientScope
                {
                    ClientId = defaultClient.Id,
                    Scope = scope
                });
            }

            // Add permissions
            var permissions = new[]
            {
                OpenIddictConstants.Permissions.Endpoints.Authorization,
                OpenIddictConstants.Permissions.Endpoints.Token,
                OpenIddictConstants.Permissions.Endpoints.EndSession,
                OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode,
                OpenIddictConstants.Permissions.GrantTypes.ClientCredentials,
                OpenIddictConstants.Permissions.GrantTypes.Password,
                OpenIddictConstants.Permissions.GrantTypes.RefreshToken,
                "oidc:scope:openid",
                OpenIddictConstants.Permissions.Scopes.Email,
                OpenIddictConstants.Permissions.Scopes.Profile,
                OpenIddictConstants.Permissions.Scopes.Roles,
                OpenIddictConstants.Permissions.ResponseTypes.Code
            };

            foreach (var permission in permissions)
            {
                _context.ClientPermissions.Add(new ClientPermission
                {
                    ClientId = defaultClient.Id,
                    Permission = permission
                });
            }

            await _context.SaveChangesAsync();
            _logger.LogInformation("Created default client 'postman_client'");
        }

        // Sync all enabled clients with OpenIddict
        var enabledClients = await GetEnabledClientsAsync();
        foreach (var client in enabledClients)
        {
            await SyncClientWithOpenIddictAsync(client);
        }
    }

    public async Task<IEnumerable<Client>> GetEnabledClientsAsync()
    {
        return await _context.Clients
            .Include(c => c.Realm)
            .Include(c => c.RedirectUris)
            .Include(c => c.PostLogoutUris)
            .Include(c => c.Scopes)
            .Include(c => c.Permissions)
            .Where(c => c.IsEnabled && c.Realm.IsEnabled)
            .ToListAsync();
    }

    public async Task SyncClientWithOpenIddictAsync(Client client)
    {
        try
        {
            // Remove existing OpenIddict application if it exists
            var existingClient = await _applicationManager.FindByClientIdAsync(client.ClientId);
            if (existingClient != null)
            {
                await _applicationManager.DeleteAsync(existingClient);
            }

            // Create new OpenIddict application descriptor
            var descriptor = new OpenIddictApplicationDescriptor
            {
                ClientId = client.ClientId,
                ClientSecret = client.ClientSecret,
                DisplayName = client.Name,
                ClientType = client.ClientType == ClientType.Public 
                    ? OpenIddictConstants.ClientTypes.Public 
                    : OpenIddictConstants.ClientTypes.Confidential
            };

            // Add permissions based on client configuration
            if (client.AllowAuthorizationCodeFlow)
            {
                descriptor.Permissions.Add(OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode);
                descriptor.Permissions.Add(OpenIddictConstants.Permissions.Endpoints.Authorization);
                descriptor.Permissions.Add(OpenIddictConstants.Permissions.ResponseTypes.Code);
            }

            if (client.AllowClientCredentialsFlow)
            {
                descriptor.Permissions.Add(OpenIddictConstants.Permissions.GrantTypes.ClientCredentials);
            }

            if (client.AllowPasswordFlow)
            {
                descriptor.Permissions.Add(OpenIddictConstants.Permissions.GrantTypes.Password);
            }

            if (client.AllowRefreshTokenFlow)
            {
                descriptor.Permissions.Add(OpenIddictConstants.Permissions.GrantTypes.RefreshToken);
            }

            // Always add token endpoint
            descriptor.Permissions.Add(OpenIddictConstants.Permissions.Endpoints.Token);

            // Add configured permissions
            foreach (var permission in client.Permissions)
            {
                descriptor.Permissions.Add(permission.Permission);
            }

            // Add redirect URIs
            foreach (var redirectUri in client.RedirectUris)
            {
                descriptor.RedirectUris.Add(new Uri(redirectUri.Uri));
            }

            // Add post-logout redirect URIs
            foreach (var postLogoutUri in client.PostLogoutUris)
            {
                descriptor.PostLogoutRedirectUris.Add(new Uri(postLogoutUri.Uri));
            }

            // Create the OpenIddict application
            await _applicationManager.CreateAsync(descriptor);

            _logger.LogInformation("Successfully synced client '{ClientId}' with OpenIddict", client.ClientId);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to sync client '{ClientId}' with OpenIddict", client.ClientId);
            throw;
        }
    }
}