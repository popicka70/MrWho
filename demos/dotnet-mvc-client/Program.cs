using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using MrWhoOidc.Client.DependencyInjection;
using MrWhoOidc.RazorClient.Services;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddRazorPages();
builder.Services.AddHttpContextAccessor();
builder.Services.AddMrWhoOidcClient(builder.Configuration, "MrWhoOidc");

// OBO API Client (On-Behalf-Of: user context)
builder.Services.AddHttpClient<OboApiClient>((sp, client) =>
    {
        var config = sp.GetRequiredService<IConfiguration>();
        var baseAddress = config["OboApi:BaseAddress"];
        if (!string.IsNullOrWhiteSpace(baseAddress) && Uri.TryCreate(baseAddress, UriKind.Absolute, out var uri))
        {
            client.BaseAddress = uri;
        }
    })
    .ConfigurePrimaryHttpMessageHandler(sp =>
    {
        var config = sp.GetRequiredService<IConfiguration>();
        var acceptAny = config.GetValue<bool>("MrWhoOidc:DangerousAcceptAnyServerCertificateValidator");
        if (acceptAny)
        {
            return new HttpClientHandler
            {
                ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator
            };
        }
        return new HttpClientHandler();
    })
    .AddMrWhoOnBehalfOfTokenHandler("obo-demo-api", async (sp, ct) =>
    {
        var accessor = sp.GetRequiredService<IHttpContextAccessor>();
        var context = accessor.HttpContext;
        if (context is null) return null;
        return await context.GetTokenAsync("access_token");
    });

// M2M API Client (Client Credentials: machine context)
// Only add token handler when a valid ClientCredentials registration exists.
var httpClientBuilder = builder.Services.AddHttpClient<M2MApiClient>((sp, client) =>
{
    var config = sp.GetRequiredService<IConfiguration>();
    var baseAddress = config["M2MApi:BaseAddress"];
    if (!string.IsNullOrWhiteSpace(baseAddress) && Uri.TryCreate(baseAddress, UriKind.Absolute, out var uri))
    {
        client.BaseAddress = uri;
    }
})
.ConfigurePrimaryHttpMessageHandler(sp =>
{
    var config = sp.GetRequiredService<IConfiguration>();
    var acceptAny = config.GetValue<bool>("MrWhoOidc:DangerousAcceptAnyServerCertificateValidator");
    if (acceptAny)
    {
        return new HttpClientHandler
        {
            ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator
        };
    }
    return new HttpClientHandler();
});

var m2mRegistration = builder.Configuration.GetSection("MrWhoOidc:ClientCredentials:obo-demo-api");
var hasScopes = m2mRegistration.GetSection("Scopes").GetChildren().Any();
var hasResource = !string.IsNullOrWhiteSpace(m2mRegistration["Resource"]);
var hasAudience = !string.IsNullOrWhiteSpace(m2mRegistration["Audience"]);

if (m2mRegistration.Exists() && (hasScopes || hasResource || hasAudience))
{
    httpClientBuilder.AddMrWhoClientCredentialsTokenHandler("obo-demo-api");
}

builder.Services.AddAuthentication(options =>
{
    options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
})
.AddCookie(options =>
{
    options.LoginPath = "/auth/login";
    options.LogoutPath = "/auth/logout";
});

builder.Services.AddAuthorization();

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
app.MapRazorPages();

app.Run();
