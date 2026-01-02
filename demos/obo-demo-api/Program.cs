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

// GET /me - Returns information about the token subject and actor
app.MapGet("/me", async (ClaimsPrincipal user, HttpContext context, IHttpClientFactory httpClientFactory, IOptionsMonitor<MrWhoOidcClientOptions> optionsMonitor, ILogger<Program> logger) =>
{
    // Extract subject claims
    var subject = user.FindFirst("sub")?.Value;
    var name = user.FindFirst("name")?.Value;
    var email = user.FindFirst("email")?.Value;
    
    // Extract actor claim (populated by OBO)
    var actClaim = user.FindFirst("act")?.Value;
    string? actorClientId = null;
    if (!string.IsNullOrEmpty(actClaim))
    {
        try 
        {
            // Parse {"sub": "dotnet-mvc-demo"} from act claim
            using var doc = JsonDocument.Parse(actClaim);
            if (doc.RootElement.TryGetProperty("sub", out var subProp))
            {
                actorClientId = subProp.GetString();
            }
        }
        catch
        {
            // Fallback if not JSON
            actorClientId = actClaim;
        }
    }

    // Call UserInfo endpoint to get more details (since access token might be minimal)
    JsonElement? userInfo = null;
    var accessToken = await context.GetTokenAsync("access_token");
    if (!string.IsNullOrEmpty(accessToken))
    {
        var clientOptions = optionsMonitor.CurrentValue;
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
                userInfo = await response.Content.ReadFromJsonAsync<JsonElement>();
                logger.LogInformation("UserInfo response: {UserInfo}", userInfo);
                
                // Enrich local variables if missing from token
                if (string.IsNullOrEmpty(name) && userInfo.Value.TryGetProperty("name", out var nameProp))
                {
                    name = nameProp.GetString();
                }
                if (string.IsNullOrEmpty(email) && userInfo.Value.TryGetProperty("email", out var emailProp))
                {
                    email = emailProp.GetString();
                }
            }
            else
            {
                logger.LogWarning("UserInfo endpoint returned status code: {StatusCode}", response.StatusCode);
            }
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Failed to call UserInfo endpoint");
        }
    }
    
    return Results.Ok(new
    {
        message = "Called on behalf of user",
        subject,
        name,
        email,
        actor = actorClientId,
        audience = user.FindFirst("aud")?.Value,
        scopes = user.FindFirst("scope")?.Value?.Split(' ', StringSplitOptions.RemoveEmptyEntries),
        issuedAt = user.FindFirst("iat")?.Value,
        expiresAt = user.FindFirst("exp")?.Value,
        userInfo // Include full user info for visibility
    });
}).RequireAuthorization();

app.Run();
