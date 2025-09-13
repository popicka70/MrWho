using MrWho.ClientAuth;
using MrWho.ClientAuth.M2M; // M2M helpers
using MrWho.ClientAuth.Par; // PAR support
using Microsoft.IdentityModel.Tokens; // algorithms (kept for potential future use)

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddRazorPages();

var authority = builder.Configuration["Authentication:Authority"] ?? "https://localhost:7113";
var clientSecret = builder.Configuration["Authentication:ClientSecret"];

// PAR client
builder.Services.AddMrWhoParClient(o =>
{
    o.ParEndpoint = new Uri(authority.TrimEnd('/') + "/connect/par");
    o.AutoPushQueryLengthThreshold = 400; 
});

var apiBase = new Uri(builder.Configuration["DemoApi:BaseUrl"] ?? "https://localhost:7162/");

builder.Services.AddMrWhoClientCredentialsApi(
    name: "DemoApiM2M",
    baseAddress: apiBase,
    configure: opt =>
    {
        opt.Authority = authority;
        opt.ClientId = builder.Configuration["M2M:ClientId"] ?? "mrwho_demo_api_client";
        opt.ClientSecret = builder.Configuration["M2M:ClientSecret"] ?? "DemoApiClientSecret2025!";
        opt.Scopes = new[] { "api.read" };
        opt.AcceptAnyServerCertificate = builder.Environment.IsDevelopment();
    });

builder.Services.AddMrWhoUserAccessTokenApi(
    name: "DemoApiUser",
    baseAddress: apiBase);

builder.Services.AddMrWhoAuthentication(options =>
{
    options.Authority = authority;
    options.ClientId = builder.Configuration["Authentication:ClientId"] ?? "mrwho_demo1";
    options.ClientSecret = clientSecret; // null for public
    options.SaveTokens = true;
    options.SignedOutCallbackPath = "/signout-callback-oidc";

    options.Scopes.Clear();
    options.Scopes.Add("openid");
    options.Scopes.Add("profile");
    options.Scopes.Add("email");
    options.Scopes.Add("roles");
    options.Scopes.Add("offline_access");
    options.Scopes.Add("api.read");

    if (builder.Environment.IsDevelopment())
    {
        options.AllowSelfSignedCertificates = true;
    }

    options.ConfigureOpenIdConnect = oidc =>
    {
        var existing = oidc.Events.OnRedirectToIdentityProvider;
        oidc.Events.OnRedirectToIdentityProvider = async ctx =>
        {
            if (string.Equals(ctx.ProtocolMessage.ResponseType, "code", StringComparison.OrdinalIgnoreCase))
            {
                try
                {
                    var par = ctx.HttpContext.RequestServices.GetService(typeof(IPushedAuthorizationService)) as IPushedAuthorizationService;
                    if (par != null)
                    {
                        string? codeChallenge = ctx.ProtocolMessage.GetParameter("code_challenge");
                        string? codeChallengeMethod = ctx.ProtocolMessage.GetParameter("code_challenge_method");

                        var authReq = new AuthorizationRequest
                        {
                            ClientId = ctx.ProtocolMessage.ClientId!,
                            RedirectUri = ctx.ProtocolMessage.RedirectUri!,
                            Scope = ctx.ProtocolMessage.Scope,
                            ResponseType = ctx.ProtocolMessage.ResponseType!,
                            State = ctx.ProtocolMessage.State,
                            CodeChallenge = codeChallenge,
                            CodeChallengeMethod = codeChallengeMethod
                            // JAR request object intentionally omitted
                        };
                        var (result, error) = await par.PushAsync(authReq, ctx.HttpContext.RequestAborted);
                        if (result != null)
                        {
                            var state = ctx.ProtocolMessage.State;
                            var nonce = ctx.ProtocolMessage.Nonce;
                            var clientIdLocal = ctx.ProtocolMessage.ClientId;
                            ctx.ProtocolMessage.Parameters.Clear();
                            ctx.ProtocolMessage.ClientId = clientIdLocal;
                            if (!string.IsNullOrEmpty(state)) ctx.ProtocolMessage.State = state;
                            if (!string.IsNullOrEmpty(nonce)) ctx.ProtocolMessage.Nonce = nonce;
                            ctx.ProtocolMessage.SetParameter("request_uri", result.RequestUri);
                        }
                        else if (error != null && error.ErrorDescription?.Contains("PAR disabled", StringComparison.OrdinalIgnoreCase) == true)
                        {
                            // fallback
                        }
                        else if (error != null)
                        {
                            throw new InvalidOperationException($"PAR push failed: {error.Error} {error.ErrorDescription}");
                        }
                    }
                }
                catch { }
            }
            if (existing != null) await existing(ctx);
        };
    };
});

var app = builder.Build();

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/health", () => Results.Ok("OK"));

app.MapMrWhoBackChannelLogoutEndpoint();
app.MapMrWhoLoginEndpoint();
app.MapMrWhoLogoutEndpoints();

app.MapGet("/demo/m2m-call", async (IHttpClientFactory factory) =>
{
    var client = factory.CreateClient("DemoApiM2M");
    var resp = await client.GetAsync("WeatherForecast");
    var body = await resp.Content.ReadAsStringAsync();
    return Results.Json(new { status = (int)resp.StatusCode, ok = resp.IsSuccessStatusCode, body });
});

app.MapGet("/demo/user-call", async (IHttpClientFactory factory, HttpContext ctx) =>
{
    if (ctx.User?.Identity?.IsAuthenticated != true)
    {
        return Results.Unauthorized();
    }
    var client = factory.CreateClient("DemoApiUser");
    var resp = await client.GetAsync("WeatherForecast");
    var body = await resp.Content.ReadAsStringAsync();
    return Results.Json(new { status = (int)resp.StatusCode, ok = resp.IsSuccessStatusCode, body });
}).RequireAuthorization();

app.MapRazorPages();

app.Run();
