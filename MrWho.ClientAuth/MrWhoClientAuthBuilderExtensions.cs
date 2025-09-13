using System.Net.Http;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;

namespace MrWho.ClientAuth;

public static class MrWhoClientAuthBuilderExtensions
{
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
        var oidcScheme = string.IsNullOrWhiteSpace(key) ? MrWhoClientAuthDefaults.OpenIdConnectScheme : MrWhoClientAuthDefaults.BuildOidcScheme(key);

        bool requireHttps = options.RequireHttpsMetadata ?? options.Authority.StartsWith("https://", StringComparison.OrdinalIgnoreCase);

        var builder = services.AddAuthentication(auth =>
        {
            auth.DefaultScheme = cookieScheme;
            auth.DefaultChallengeScheme = oidcScheme;
            auth.DefaultSignOutScheme = oidcScheme;
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

        var externalConfigure = options.ConfigureOpenIdConnect;

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
            if (!string.IsNullOrWhiteSpace(options.SignedOutRedirectUri)) oidc.SignedOutRedirectUri = options.SignedOutRedirectUri;

            oidc.TokenValidationParameters = new TokenValidationParameters { NameClaimType = "name", RoleClaimType = "role" };
            oidc.Scope.Clear(); foreach (var s in options.Scopes) oidc.Scope.Add(s);

            var metadata = options.ResolveMetadataAddress();
            var httpRetriever = new HttpDocumentRetriever { RequireHttps = requireHttps };
            if (options.AllowSelfSignedCertificates)
            {
                var handler = new HttpClientHandler { ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator };
                var httpClient = new HttpClient(handler, disposeHandler: true);
                httpRetriever = new HttpDocumentRetriever(httpClient) { RequireHttps = requireHttps };
                oidc.BackchannelHttpHandler = handler;
            }
            oidc.MetadataAddress = metadata;
            oidc.ConfigurationManager = new ConfigurationManager<OpenIdConnectConfiguration>(metadata, new OpenIdConnectConfigurationRetriever(), httpRetriever);

            oidc.ClaimActions.Clear();
            foreach (var claim in new[] { "iss","aud","exp","iat","nonce","at_hash","azp","oi_au_id","oi_tbn_id" }) oidc.ClaimActions.DeleteClaim(claim);
            oidc.ClaimActions.MapJsonKey("sub","sub");
            oidc.ClaimActions.MapJsonKey("name","name");
            oidc.ClaimActions.MapJsonKey("given_name","given_name");
            oidc.ClaimActions.MapJsonKey("family_name","family_name");
            oidc.ClaimActions.MapJsonKey("email","email");
            oidc.ClaimActions.MapJsonKey("email_verified","email_verified");
            oidc.ClaimActions.MapJsonKey("preferred_username","preferred_username");
            oidc.ClaimActions.MapJsonKey("phone_number","phone_number");
            oidc.ClaimActions.MapJsonKey("phone_number_verified","phone_number_verified");
            oidc.ClaimActions.MapJsonKey("role","role");

            oidc.Events = new OpenIdConnectEvents
            {
                OnRedirectToIdentityProvider = ctx =>
                {
                    // Only ensure correct authorize endpoint, no custom PAR logic
                    var authority = ctx.Options.Authority?.TrimEnd('/') ?? string.Empty;
                    if (!string.IsNullOrEmpty(authority))
                    {
                        var desiredAuthorize = $"{authority}/connect/authorize";
                        if (!string.Equals(ctx.ProtocolMessage.IssuerAddress, desiredAuthorize, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.ProtocolMessage.IssuerAddress = desiredAuthorize;
                        }
                    }
                    externalConfigure?.Invoke(ctx.Options);
                    return Task.CompletedTask;
                },
                OnRedirectToIdentityProviderForSignOut = ctx => Task.CompletedTask,
                OnTokenResponseReceived = ctx => Task.CompletedTask,
                OnTokenValidated = ctx =>
                {
                    var identity = ctx.Principal?.Identities?.FirstOrDefault();
                    if (identity != null && !identity.HasClaim(c => c.Type == "name"))
                    {
                        var value = identity.FindFirst("preferred_username")?.Value ?? identity.FindFirst("email")?.Value ?? identity.FindFirst("sub")?.Value;
                        if (!string.IsNullOrWhiteSpace(value)) identity.AddClaim(new Claim("name", value));
                    }
                    return Task.CompletedTask;
                },
                OnAuthenticationFailed = ctx => Task.CompletedTask
            };

            options.ConfigureOpenIdConnect?.Invoke(oidc);
        });

        return builder;
    }
}
