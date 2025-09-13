using MrWho.ClientAuth;
using MrWho.ClientAuth.M2M;
using MrWho.ClientAuth.Par;
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddRazorPages();

var authority = builder.Configuration["Authentication:Authority"] ?? "https://localhost:7113";
var clientSecret = builder.Configuration["Authentication:ClientSecret"];

// PAR client
builder.Services.AddMrWhoParClient(o =>
{
    o.ParEndpoint = new Uri(authority.TrimEnd('/') + "/connect/par");
    o.AutoPushQueryLengthThreshold = 400; // lower for demo
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
    options.AutoParPush = true; // enabled by default but explicit for clarity

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
