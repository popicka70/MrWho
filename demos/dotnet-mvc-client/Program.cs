using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using MrWhoOidc.Client.DependencyInjection;
using MrWhoOidc.RazorClient.Services;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddRazorPages();
builder.Services.AddHttpContextAccessor();
builder.Services.AddMrWhoOidcClient(builder.Configuration, "MrWhoOidc");

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
