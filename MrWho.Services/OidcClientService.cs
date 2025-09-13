// ...existing usings...
using MrWho.Shared;

namespace MrWho.Services;

public class OidcClientService : IOidcClientService
{
    // ...existing fields/ctor...

    private OpenIddictApplicationDescriptor BuildDescriptor(Client client)
    {
        var descriptor = new OpenIddictApplicationDescriptor
        {
            ClientId = client.ClientId,
            ClientSecret = client.ClientSecret,
            DisplayName = client.Name,
            ClientType = client.ClientType == ClientType.Public ? OpenIddictConstants.ClientTypes.Public : OpenIddictConstants.ClientTypes.Confidential
        };

        if (client.AllowAuthorizationCodeFlow)
        {
            descriptor.Permissions.Add(OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode);
            descriptor.Permissions.Add(OpenIddictConstants.Permissions.Endpoints.Authorization);
            descriptor.Permissions.Add(OpenIddictConstants.Permissions.ResponseTypes.Code);
        }
        if (client.AllowClientCredentialsFlow)
            descriptor.Permissions.Add(OpenIddictConstants.Permissions.GrantTypes.ClientCredentials);
        if (client.AllowPasswordFlow)
            descriptor.Permissions.Add(OpenIddictConstants.Permissions.GrantTypes.Password);
        if (client.AllowRefreshTokenFlow)
            descriptor.Permissions.Add(OpenIddictConstants.Permissions.GrantTypes.RefreshToken);
        descriptor.Permissions.Add(OpenIddictConstants.Permissions.Endpoints.Token);

        // PAR mode handling
        if (client.ParMode is PushedAuthorizationMode.Enabled or PushedAuthorizationMode.Required)
        {
            descriptor.Permissions.Add(OpenIddictConstants.Permissions.Endpoints.PushedAuthorization);
        }
        if (client.ParMode is PushedAuthorizationMode.Required)
        {
            descriptor.Requirements.Add(OpenIddictConstants.Requirements.Features.PushedAuthorizationRequests);
        }

        var (hasOpenId, scopePerms) = BuildScopePermissions(client.Scopes.Select(s => s.Scope));
        foreach (var p in scopePerms) descriptor.Permissions.Add(p);
        if (hasOpenId)
            descriptor.Permissions.Add(OpenIddictConstants.Permissions.Endpoints.EndSession);

        // endpoint access
        if (client.AllowAccessToUserInfoEndpoint == true && hasOpenId)
            descriptor.Permissions.Add(UserInfoEndpointPermission);
        if (client.AllowAccessToRevocationEndpoint == true)
            descriptor.Permissions.Add(RevocationEndpointPermission);
        if (client.AllowAccessToIntrospectionEndpoint == true)
            descriptor.Permissions.Add(IntrospectionEndpointPermission);

        foreach (var permission in client.Permissions.Select(p => p.Permission))
        {
            if (permission.StartsWith("scp:") || permission.StartsWith("oidc:scope:"))
                continue;
            if (permission is "endpoints:userinfo" or "endpoints:revocation" or "endpoints:introspection" ||
                permission is "endpoints/userinfo" or "endpoints/revocation" or "endpoints/introspection")
                continue;
            if (!descriptor.Permissions.Contains(permission))
                descriptor.Permissions.Add(permission);
        }

        foreach (var redirect in client.RedirectUris)
            descriptor.RedirectUris.Add(new Uri(redirect.Uri));
        foreach (var postLogout in client.PostLogoutUris)
            descriptor.PostLogoutRedirectUris.Add(new Uri(postLogout.Uri));

        return descriptor;
    }

    // ...rest unchanged...
}
