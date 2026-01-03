using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using MrWhoOidc.Client.DependencyInjection;
using MrWhoOidc.Client.Jwks;
using MrWhoOidc.Client.Options;
using Microsoft.Extensions.Options;

var builder = WebApplication.CreateBuilder(args);

// Add MrWhoOidc Client services (Discovery, JWKS caching)
builder.Services.AddMrWhoOidcClient(builder.Configuration, "MrWhoOidc");

// Configure Authentication
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer();

builder.Services.AddAuthorization();

// Configure JWT Bearer options to use MrWhoOidc JWKS cache
builder.Services.AddOptions<JwtBearerOptions>(JwtBearerDefaults.AuthenticationScheme)
    .Configure<IServiceProvider>((options, sp) =>
    {
        var clientOptions = sp.GetRequiredService<IOptionsMonitor<MrWhoOidcClientOptions>>().CurrentValue;
        
        options.RequireHttpsMetadata = clientOptions.RequireHttpsMetadata;
        options.TokenValidationParameters.ValidateIssuer = true;
        options.TokenValidationParameters.ValidIssuer = clientOptions.Issuer;
        
        // Validate audience
        var expectedAudience = clientOptions.Audience ?? clientOptions.Resource ?? "obo-demo-api";
        options.TokenValidationParameters.ValidateAudience = true;
        options.TokenValidationParameters.ValidAudience = expectedAudience;
        
        options.TokenValidationParameters.ValidateIssuerSigningKey = true;
        options.TokenValidationParameters.RequireSignedTokens = true;
        
        // Use shared JWKS cache for key resolution
        options.TokenValidationParameters.IssuerSigningKeyResolver = (token, securityToken, kid, parameters) =>
        {
            var cache = sp.GetRequiredService<IMrWhoJwksCache>();
            var jwks = cache.GetAsync().AsTask().GetAwaiter().GetResult();
            IEnumerable<JsonWebKey> keys = jwks.Keys;
            if (!string.IsNullOrEmpty(kid))
            {
                keys = keys.Where(k => string.Equals(k.Kid, kid, StringComparison.Ordinal));
            }
            return keys.Cast<SecurityKey>();
        };
    });

// Register HTTP client for UserInfo endpoint calls
builder.Services.AddHttpClient("UserInfoClient")
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

builder.Services.AddHealthChecks();

var app = builder.Build();

app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();

app.MapHealthChecks("/health");

// Helper function to fetch user info from IdP
async Task<JsonElement?> FetchUserInfoAsync(string accessToken, 
    MrWhoOidcClientOptions clientOptions, 
    IHttpClientFactory httpClientFactory, 
    ILogger logger)
{
    var userInfoEndpoint = $"{clientOptions.Issuer?.TrimEnd('/')}/userinfo";
    var client = httpClientFactory.CreateClient("UserInfoClient");
    
    var request = new HttpRequestMessage(HttpMethod.Get, userInfoEndpoint);
    request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);
    
    try 
    {
        logger.LogInformation("Calling UserInfo endpoint: {Endpoint}", userInfoEndpoint);
        var response = await client.SendAsync(request);
        if (response.IsSuccessStatusCode)
        {
            var userInfo = await response.Content.ReadFromJsonAsync<JsonElement>();
            logger.LogInformation("UserInfo response retrieved");
            return userInfo;
        }
        logger.LogWarning("UserInfo endpoint returned status code: {StatusCode}", response.StatusCode);
    }
    catch (Exception ex)
    {
        logger.LogError(ex, "Failed to call UserInfo endpoint");
    }
    return null;
}

// GET /identity - Unified endpoint that returns info based on call type (OBO vs M2M)
app.MapGet("/identity", async (ClaimsPrincipal user, HttpContext context, 
    IHttpClientFactory httpClientFactory, 
    IOptionsMonitor<MrWhoOidcClientOptions> optionsMonitor, 
    ILogger<Program> logger) =>
{
    var subject = user.FindFirst("sub")?.Value;
    var audience = user.FindFirst("aud")?.Value;
    var scopes = user.FindFirst("scope")?.Value?.Split(' ', StringSplitOptions.RemoveEmptyEntries);
    var issuedAt = user.FindFirst("iat")?.Value;
    var expiresAt = user.FindFirst("exp")?.Value;
    
    // Check for actor claim to determine call type
    var actClaim = user.FindFirst("act")?.Value;
    
    if (!string.IsNullOrEmpty(actClaim))
    {
        // --- OBO CALL: Token has an actor ---
        string? actorClientId = null;
        try 
        {
            using var doc = JsonDocument.Parse(actClaim);
            if (doc.RootElement.TryGetProperty("sub", out var subProp))
            {
                actorClientId = subProp.GetString();
            }
        }
        catch
        {
            actorClientId = actClaim;
        }

        // Fetch user info from IdP
        JsonElement? userInfo = null;
        var accessToken = await context.GetTokenAsync("access_token");
        if (!string.IsNullOrEmpty(accessToken))
        {
            userInfo = await FetchUserInfoAsync(accessToken, optionsMonitor.CurrentValue, 
                httpClientFactory, logger);
        }

        var name = user.FindFirst("name")?.Value;
        var email = user.FindFirst("email")?.Value;
        
        // Enrich from userInfo if missing
        if (userInfo.HasValue)
        {
            if (string.IsNullOrEmpty(name) && userInfo.Value.TryGetProperty("name", out var n))
                name = n.GetString();
            if (string.IsNullOrEmpty(email) && userInfo.Value.TryGetProperty("email", out var e))
                email = e.GetString();
        }

        return Results.Ok(new
        {
            type = "user",
            message = "Called on behalf of user (OBO flow)",
            subject,
            name,
            email,
            actor = actorClientId,
            audience,
            scopes,
            issuedAt,
            expiresAt,
            userInfo
        });
    }
    else
    {
        // --- M2M CALL: No actor, subject is the client ---
        var clientId = user.FindFirst("client_id")?.Value 
                    ?? user.FindFirst("azp")?.Value 
                    ?? subject;
        
        return Results.Ok(new
        {
            type = "machine",
            message = "Called as machine identity (M2M / Client Credentials flow)",
            clientId,
            subject,
            audience,
            scopes,
            issuedAt,
            expiresAt
        });
    }
}).RequireAuthorization();

// GET /me - Backward compatibility alias
app.MapGet("/me", async (HttpContext context) =>
{
    // Redirect to /identity
    context.Response.Redirect("/identity");
    return Results.Empty;
}).RequireAuthorization();

app.Run();
