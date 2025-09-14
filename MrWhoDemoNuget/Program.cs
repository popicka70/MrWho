using Microsoft.IdentityModel.Tokens;
using MrWho.ClientAuth;
using MrWho.ClientAuth.Jar; // JAR signer
using MrWho.ClientAuth.M2M;
using MrWho.ClientAuth.Par; // PAR client

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddRazorPages();

var authority = builder.Configuration["Authentication:Authority"] ?? "https://localhost:7113";
var clientSecret = builder.Configuration["Authentication:ClientSecret"];

// Register JAR signer (HS256 with client secret for demo). For RS256 supply RsaPrivateKeyPem / certificate instead.
if (!string.IsNullOrWhiteSpace(clientSecret))
{
    builder.Services.AddMrWhoJarSigner(o =>
    {
        o.Algorithm = SecurityAlgorithms.HmacSha256; // matches default allowed list (RS256,HS256)
        o.ClientSecret = clientSecret;              // must be >=32 bytes for HS256 (demo secret should satisfy)
        o.Issuer = null;                            // defaults to client_id
        o.Audience = "mrwho";                      // server-side expected audience
    });
}

// Re-enable PAR client (Tasks 9/10). Auto threshold low so we always push quickly for demo clarity.
builder.Services.AddMrWhoParClient(o =>
{
    o.ParEndpoint = new Uri(authority.TrimEnd('/') + "/connect/par");
    o.AutoPushQueryLengthThreshold = 200; // force PAR even for short requests
    o.AutoJar = true; // ensure JAR built before push
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

    // Allow auto PAR push now that endpoint is advertised
    options.AutoParPush = true;

    // Enable JAR/JARM
    options.EnableJar = true;
    options.JarOnlyWhenLarge = false; // always create request object; PAR will carry it
    options.EnableJarm = true;

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
