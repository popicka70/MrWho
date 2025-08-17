using System.Net.Http;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;

namespace MrWho.ClientAuth;

public static class MrWhoClientAuthBuilderExtensions
{
    /// <summary>
    /// Adds cookie + OpenIdConnect authentication configured for the MrWho OIDC server.
    /// Supports per-clientId scheme names so apps can maintain isolated sessions per client.
    /// </summary>
    public static AuthenticationBuilder AddMrWhoAuthentication(
        this IServiceCollection services,
        Action<MrWhoClientAuthOptions> configure)
    {
        var options = new MrWhoClientAuthOptions();
        configure(options);

        var key = options.ClientId;
        var cookieScheme = !string.IsNullOrWhiteSpace(options.CookieScheme)
            ? options.CookieScheme!
            : (string.IsNullOrWhiteSpace(key) ? MrWhoClientAuthDefaults.CookieScheme : MrWhoClientAuthDefaults.BuildCookieScheme(key));

        var oidcScheme = string.IsNullOrWhiteSpace(key)
            ? MrWhoClientAuthDefaults.OpenIdConnectScheme
            : MrWhoClientAuthDefaults.BuildOidcScheme(key);

        // Decide default require-https if not set
        bool requireHttps = options.RequireHttpsMetadata ?? options.Authority.StartsWith("https://", StringComparison.OrdinalIgnoreCase);

        // Configure authentication with a local cookie scheme and OIDC challenge scheme
        var builder = services.AddAuthentication(auth =>
        {
            auth.DefaultScheme = cookieScheme;
            auth.DefaultChallengeScheme = oidcScheme;
        })
        .AddCookie(cookieScheme, cookie =>
        {
            cookie.Cookie.Name = $".{cookieScheme}";
            cookie.Cookie.Path = "/";
            cookie.Cookie.HttpOnly = true;
            cookie.Cookie.SecurePolicy = Microsoft.AspNetCore.Http.CookieSecurePolicy.SameAsRequest;
            cookie.Cookie.SameSite = Microsoft.AspNetCore.Http.SameSiteMode.Lax;
            cookie.ExpireTimeSpan = TimeSpan.FromHours(8);
            cookie.SlidingExpiration = true;
        });

        // OpenIdConnect resides in AspNetCore shared framework. Register via extension method from package ref.
        OpenIdConnectExtensions.AddOpenIdConnect(builder, oidcScheme, oidc =>
        {
            oidc.SignInScheme = cookieScheme;
            oidc.Authority = options.Authority.TrimEnd('/') + "/";
            oidc.ClientId = options.ClientId;
            oidc.ClientSecret = options.ClientSecret;
            oidc.ResponseType = OpenIdConnectResponseType.Code;
            oidc.UsePkce = options.UsePkce;
            oidc.SaveTokens = options.SaveTokens;
            oidc.GetClaimsFromUserInfoEndpoint = options.GetClaimsFromUserInfoEndpoint;
            oidc.RequireHttpsMetadata = requireHttps;

            oidc.CallbackPath = options.CallbackPath;
            oidc.SignedOutCallbackPath = options.SignedOutCallbackPath;
            oidc.RemoteSignOutPath = options.RemoteSignOutPath;

            // Ensure Identity.Name and roles resolve using standard OIDC claims by default
            oidc.TokenValidationParameters = new TokenValidationParameters
            {
                NameClaimType = "name",
                RoleClaimType = "role"
            };

            // Scopes
            oidc.Scope.Clear();
            foreach (var s in options.Scopes)
                oidc.Scope.Add(s);

            // Discovery: allow override of MetadataAddress while still using Authority for browser redirects
            var metadata = options.ResolveMetadataAddress();
            var httpRetriever = new HttpDocumentRetriever { RequireHttps = requireHttps };

            if (options.AllowSelfSignedCertificates)
            {
                var handler = new HttpClientHandler
                {
                    ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator
                };
                var httpClient = new HttpClient(handler, disposeHandler: true);
                httpRetriever = new HttpDocumentRetriever(httpClient) { RequireHttps = requireHttps };
                oidc.BackchannelHttpHandler = handler;
            }

            oidc.MetadataAddress = metadata;
            oidc.ConfigurationManager = new ConfigurationManager<OpenIdConnectConfiguration>(
                metadata,
                new OpenIdConnectConfigurationRetriever(),
                httpRetriever);

            // Claims: keep ID token claims only by default (UserInfo often locked down)
            oidc.ClaimActions.Clear();
            oidc.ClaimActions.DeleteClaim("iss");
            oidc.ClaimActions.DeleteClaim("aud");
            oidc.ClaimActions.DeleteClaim("exp");
            oidc.ClaimActions.DeleteClaim("iat");
            oidc.ClaimActions.DeleteClaim("nonce");
            oidc.ClaimActions.DeleteClaim("at_hash");
            oidc.ClaimActions.DeleteClaim("azp");
            oidc.ClaimActions.DeleteClaim("oi_au_id");
            oidc.ClaimActions.DeleteClaim("oi_tbn_id");

            oidc.ClaimActions.MapJsonKey("sub", "sub");
            oidc.ClaimActions.MapJsonKey("name", "name");
            oidc.ClaimActions.MapJsonKey("given_name", "given_name");
            oidc.ClaimActions.MapJsonKey("family_name", "family_name");
            oidc.ClaimActions.MapJsonKey("email", "email");
            oidc.ClaimActions.MapJsonKey("email_verified", "email_verified");
            oidc.ClaimActions.MapJsonKey("preferred_username", "preferred_username");
            oidc.ClaimActions.MapJsonKey("phone_number", "phone_number");
            oidc.ClaimActions.MapJsonKey("phone_number_verified", "phone_number_verified");
            oidc.ClaimActions.MapJsonKey("role", "role");

            // Events: ensure correct authorize endpoint override for the public Authority
            oidc.Events = new OpenIdConnectEvents
            {
                OnRedirectToIdentityProvider = ctx =>
                {
                    var logger = ctx.HttpContext.RequestServices.GetRequiredService<ILoggerFactory>()
                        .CreateLogger("MrWho.ClientAuth.OIDC");
                    logger.LogInformation("Redirecting to identity provider: client_id={ClientId}", ctx.ProtocolMessage.ClientId);

                    var authority = ctx.Options.Authority?.TrimEnd('/') ?? string.Empty;
                    if (!string.IsNullOrEmpty(authority))
                    {
                        var desiredAuthorize = $"{authority}/connect/authorize";
                        if (!string.Equals(ctx.ProtocolMessage.IssuerAddress, desiredAuthorize, StringComparison.OrdinalIgnoreCase))
                        {
                            logger.LogDebug("Overriding IssuerAddress from {From} to {To}", ctx.ProtocolMessage.IssuerAddress, desiredAuthorize);
                            ctx.ProtocolMessage.IssuerAddress = desiredAuthorize;
                        }
                    }
                    return Task.CompletedTask;
                },
                OnTokenResponseReceived = ctx =>
                {
                    var logger = ctx.HttpContext.RequestServices.GetRequiredService<ILoggerFactory>()
                        .CreateLogger("MrWho.ClientAuth.OIDC");
                    logger.LogInformation("Token response received. HasAccessToken={HasAT}, HasRefreshToken={HasRT}",
                        !string.IsNullOrEmpty(ctx.TokenEndpointResponse.AccessToken),
                        !string.IsNullOrEmpty(ctx.TokenEndpointResponse.RefreshToken));
                    return Task.CompletedTask;
                },
                OnTokenValidated = ctx =>
                {
                    // Ensure a usable display name so HttpContext.User.Identity.Name is never null
                    var identity = ctx.Principal?.Identities?.FirstOrDefault();
                    if (identity != null)
                    {
                        // If there's no "name" claim, try to synthesize one from preferred_username, email, then sub
                        bool hasName = identity.HasClaim(c => c.Type == "name");
                        if (!hasName)
                        {
                            var value = identity.FindFirst("preferred_username")?.Value
                                        ?? identity.FindFirst("email")?.Value
                                        ?? identity.FindFirst("sub")?.Value;
                            if (!string.IsNullOrWhiteSpace(value))
                            {
                                identity.AddClaim(new Claim("name", value));
                            }
                        }
                    }
                    return Task.CompletedTask;
                },
                OnAuthenticationFailed = ctx =>
                {
                    var logger = ctx.HttpContext.RequestServices.GetRequiredService<ILoggerFactory>()
                        .CreateLogger("MrWho.ClientAuth.OIDC");
                    logger.LogError(ctx.Exception, "Authentication failed");
                    return Task.CompletedTask;
                }
            };

            // Allow consumer customization
            options.ConfigureOpenIdConnect?.Invoke(oidc);
        });

        return builder;
    }
}
