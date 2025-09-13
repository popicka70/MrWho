using System.Net.Http;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;
using MrWho.ClientAuth.Jar;
using MrWho.ClientAuth.Par; // NEW PAR
using Microsoft.Extensions.Logging; // add logging extensions

namespace MrWho.ClientAuth;

public static class MrWhoClientAuthBuilderExtensions
{
    public static AuthenticationBuilder AddMrWhoAuthentication(this IServiceCollection services, Action<MrWhoClientAuthOptions> configure)
    {
        var options = new MrWhoClientAuthOptions();
        configure(options);

        var key = options.ClientId;
        var cookieScheme = !string.IsNullOrWhiteSpace(options.CookieScheme) ? options.CookieScheme! : (string.IsNullOrWhiteSpace(key) ? MrWhoClientAuthDefaults.CookieScheme : MrWhoClientAuthDefaults.BuildCookieScheme(key));
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
                OnRedirectToIdentityProvider = async ctx =>
                {
                    var logger = ctx.HttpContext.RequestServices.GetService<Microsoft.Extensions.Logging.ILoggerFactory>()?.CreateLogger("MrWho.ClientAuth.Redirect");
                    // Normalize authorize endpoint
                    var authority = ctx.Options.Authority?.TrimEnd('/') ?? string.Empty;
                    if (!string.IsNullOrEmpty(authority))
                    {
                        var desiredAuthorize = $"{authority}/connect/authorize";
                        if (!string.Equals(ctx.ProtocolMessage.IssuerAddress, desiredAuthorize, StringComparison.OrdinalIgnoreCase))
                            ctx.ProtocolMessage.IssuerAddress = desiredAuthorize;
                    }

                    // JARM
                    if (options.EnableJarm && (options.ForceJarm || string.IsNullOrEmpty(ctx.ProtocolMessage.ResponseMode)))
                    {
                        ctx.ProtocolMessage.ResponseMode = "jwt";
                    }

                    bool parAttempted = false;
                    if (options.AutoParPush)
                    {
                        try
                        {
                            var parService = ctx.HttpContext.RequestServices.GetService<IPushedAuthorizationService>();
                            if (parService != null)
                            {
                                parAttempted = true;
                                var authReq = new Par.AuthorizationRequest
                                {
                                    ClientId = ctx.ProtocolMessage.ClientId!,
                                    RedirectUri = ctx.ProtocolMessage.RedirectUri!,
                                    Scope = ctx.ProtocolMessage.Scope,
                                    ResponseType = ctx.ProtocolMessage.ResponseType!,
                                    State = ctx.ProtocolMessage.State,
                                    CodeChallenge = ctx.ProtocolMessage.GetParameter("code_challenge"),
                                    CodeChallengeMethod = ctx.ProtocolMessage.GetParameter("code_challenge_method"),
                                    Nonce = ctx.ProtocolMessage.Nonce
                                };
                                // Preserve response_mode (e.g. jwt for JARM)
                                if (!string.IsNullOrEmpty(ctx.ProtocolMessage.ResponseMode))
                                    authReq.Extra["response_mode"] = ctx.ProtocolMessage.ResponseMode;
                                // If caller already put any custom params, replicate (none by default)
                                var (result, error) = await parService.PushAsync(authReq, ctx.HttpContext.RequestAborted);
                                if (result != null)
                                {
                                    // Replace outgoing parameters with PAR reference
                                    var state = ctx.ProtocolMessage.State; // keep state duplication optional
                                    var responseMode = ctx.ProtocolMessage.ResponseMode;
                                    ctx.ProtocolMessage.Parameters.Clear();
                                    ctx.ProtocolMessage.ClientId = authReq.ClientId;
                                    ctx.ProtocolMessage.SetParameter("request_uri", result.RequestUri);
                                    if (!string.IsNullOrEmpty(state)) ctx.ProtocolMessage.State = state; // optional (server also has it)
                                    if (!string.IsNullOrEmpty(responseMode)) ctx.ProtocolMessage.ResponseMode = responseMode;
                                    logger?.LogDebug("[PAR] request_uri={ReqUri} stateDup={HasState} rm={RM}", result.RequestUri, !string.IsNullOrEmpty(state), responseMode);
                                    // Skip local JAR since request is now stored server-side (JAR may have been embedded during push if options.AutoJar)
                                    externalConfigure?.Invoke(ctx.Options);
                                    return; // done
                                }
                                else if (error != null)
                                {
                                    logger?.LogWarning("[PAR] push failed {Err} {Desc}; falling back to direct auth (and JAR if enabled)", error.Error, error.ErrorDescription);
                                }
                            }
                        }
                        catch (Exception ex)
                        {
                            logger?.LogWarning(ex, "[PAR] unexpected failure; continuing without PAR");
                        }
                    }

                    // Local JAR only if PAR not used or failed
                    if (options.EnableJar && !parAttempted)
                    {
                        try
                        {
                            var signer = ctx.HttpContext.RequestServices.GetService<IJarRequestObjectSigner>();
                            if (signer != null)
                            {
                                bool needJar = true;
                                if (options.JarOnlyWhenLarge)
                                {
                                    var scope = ctx.ProtocolMessage.Scope ?? string.Join(' ', ctx.Options.Scope);
                                    var approx = $"client_id={ctx.ProtocolMessage.ClientId}&redirect_uri={ctx.ProtocolMessage.RedirectUri}&response_type={ctx.ProtocolMessage.ResponseType}&scope={scope}&state={ctx.ProtocolMessage.State}";
                                    needJar = approx.Length > options.JarQueryLengthThreshold;
                                }
                                if (needJar)
                                {
                                    var jarReq = new JarRequest
                                    {
                                        ClientId = ctx.ProtocolMessage.ClientId!,
                                        RedirectUri = ctx.ProtocolMessage.RedirectUri!,
                                        Scope = ctx.ProtocolMessage.Scope,
                                        ResponseType = ctx.ProtocolMessage.ResponseType!,
                                        State = ctx.ProtocolMessage.State,
                                        CodeChallenge = ctx.ProtocolMessage.GetParameter("code_challenge"),
                                        CodeChallengeMethod = ctx.ProtocolMessage.GetParameter("code_challenge_method"),
                                        // NOTE: nonce is added later in server pipeline; we don't have direct access here pre-generation
                                    };
                                    var jwt = await signer.CreateRequestObjectAsync(jarReq, ctx.HttpContext.RequestAborted);
                                    var state = ctx.ProtocolMessage.State;
                                    ctx.ProtocolMessage.Parameters.Clear();
                                    ctx.ProtocolMessage.ClientId = jarReq.ClientId;
                                    ctx.ProtocolMessage.RedirectUri = jarReq.RedirectUri;
                                    ctx.ProtocolMessage.ResponseType = jarReq.ResponseType;
                                    if (!string.IsNullOrEmpty(state)) ctx.ProtocolMessage.State = state;
                                    if (!string.IsNullOrEmpty(jarReq.Scope)) ctx.ProtocolMessage.Scope = jarReq.Scope;
                                    ctx.ProtocolMessage.SetParameter("request", jwt);
                                }
                            }
                        }
                        catch { /* fail open */ }
                    }

                    externalConfigure?.Invoke(ctx.Options);
                },
                OnTokenValidated = ctx =>
                {
                    var identity = ctx.Principal?.Identities?.FirstOrDefault();
                    if (identity != null && !identity.HasClaim(c => c.Type == "name"))
                    {
                        var value = identity.FindFirst("preferred_username")?.Value ?? identity.FindFirst("email")?.Value ?? identity.FindFirst("sub")?.Value;
                        if (!string.IsNullOrWhiteSpace(value)) identity.AddClaim(new Claim("name", value));
                    }
                    return Task.CompletedTask;
                }
            };
            options.ConfigureOpenIdConnect?.Invoke(oidc);
        });

        return builder;
    }
}
