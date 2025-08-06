using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using MrWho.Data;
using MrWho.Models;
using MrWho.Shared.Models;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Xunit;

namespace MrWhoAdmin.Tests;

public class UserInfoIdentityResourcesIntegrationTest : IClassFixture<MrWhoTestWebApplicationFactory>
{
    private readonly MrWhoTestWebApplicationFactory _factory;
    private readonly HttpClient _client;

    public UserInfoIdentityResourcesIntegrationTest(MrWhoTestWebApplicationFactory factory)
    {
        _factory = factory;
        _client = _factory.CreateClient();
    }

    [Fact]
    public async Task UserInfo_WithIdentityResources_ReturnsClaimsBasedOnScopes()
    {
        // Arrange
        using var scope = _factory.Services.CreateScope();
        var context = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<IdentityUser>>();

        // Create a test user with additional claims
        var testUser = new IdentityUser
        {
            UserName = "testuser@example.com",
            Email = "testuser@example.com",
            EmailConfirmed = true,
            PhoneNumber = "+1234567890",
            PhoneNumberConfirmed = true
        };

        var userResult = await userManager.CreateAsync(testUser, "Test123!");
        Assert.True(userResult.Succeeded);

        // Add custom claims to the user
        await userManager.AddClaimAsync(testUser, new System.Security.Claims.Claim("given_name", "Test"));
        await userManager.AddClaimAsync(testUser, new System.Security.Claims.Claim("family_name", "User"));

        // Create a custom identity resource with specific claims
        var customIdentityResource = new IdentityResource
        {
            Name = "custom_profile",
            DisplayName = "Custom Profile",
            Description = "Custom profile information",
            IsEnabled = true,
            IsRequired = false,
            ShowInDiscoveryDocument = true,
            Emphasize = false,
            CreatedBy = "Test"
        };

        context.IdentityResources.Add(customIdentityResource);
        await context.SaveChangesAsync();

        // Add claims to the custom identity resource
        var claims = new[]
        {
            new IdentityResourceClaim { IdentityResourceId = customIdentityResource.Id, ClaimType = "given_name" },
            new IdentityResourceClaim { IdentityResourceId = customIdentityResource.Id, ClaimType = "family_name" },
            new IdentityResourceClaim { IdentityResourceId = customIdentityResource.Id, ClaimType = "phone_number" }
        };

        context.IdentityResourceClaims.AddRange(claims);
        await context.SaveChangesAsync();

        // Get an access token with the custom scope
        var tokenRequest = new FormUrlEncodedContent(new[]
        {
            new KeyValuePair<string, string>("grant_type", "password"),
            new KeyValuePair<string, string>("client_id", "postman_client"),
            new KeyValuePair<string, string>("client_secret", "postman_secret"),
            new KeyValuePair<string, string>("username", testUser.UserName!),
            new KeyValuePair<string, string>("password", "Test123!"),
            new KeyValuePair<string, string>("scope", "openid email custom_profile")
        });

        var tokenResponse = await _client.PostAsync("/connect/token", tokenRequest);
        tokenResponse.EnsureSuccessStatusCode();

        var tokenContent = await tokenResponse.Content.ReadAsStringAsync();
        var tokenData = JsonSerializer.Deserialize<Dictionary<string, object>>(tokenContent);
        var accessToken = tokenData!["access_token"].ToString();

        // Act - Call UserInfo endpoint with the access token
        var userInfoRequest = new HttpRequestMessage(HttpMethod.Get, "/connect/userinfo");
        userInfoRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

        var userInfoResponse = await _client.SendAsync(userInfoRequest);

        // Assert
        userInfoResponse.EnsureSuccessStatusCode();

        var userInfoContent = await userInfoResponse.Content.ReadAsStringAsync();
        var userInfo = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(userInfoContent);

        // Verify basic claims are present
        Assert.True(userInfo!.ContainsKey("sub"));
        Assert.Equal(testUser.Id, userInfo["sub"].GetString());

        // Verify email scope claims
        Assert.True(userInfo.ContainsKey("email"));
        Assert.Equal(testUser.Email, userInfo["email"].GetString());
        Assert.True(userInfo.ContainsKey("email_verified"));
        Assert.True(userInfo["email_verified"].GetBoolean());

        // Verify custom profile claims are included
        Assert.True(userInfo.ContainsKey("given_name"));
        Assert.Equal("Test", userInfo["given_name"].GetString());
        
        Assert.True(userInfo.ContainsKey("family_name"));
        Assert.Equal("User", userInfo["family_name"].GetString());
        
        Assert.True(userInfo.ContainsKey("phone_number"));
        Assert.Equal("+1234567890", userInfo["phone_number"].GetString());
    }

    [Fact]
    public async Task UserInfo_WithLimitedScopes_ReturnsOnlyRequestedClaims()
    {
        // Arrange
        using var scope = _factory.Services.CreateScope();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<IdentityUser>>();

        // Create a test user
        var testUser = new IdentityUser
        {
            UserName = "limiteduser@example.com",
            Email = "limiteduser@example.com",
            EmailConfirmed = true,
            PhoneNumber = "+9876543210",
            PhoneNumberConfirmed = true
        };

        var userResult = await userManager.CreateAsync(testUser, "Test123!");
        Assert.True(userResult.Succeeded);

        // Get an access token with only openid scope (no email, no profile)
        var tokenRequest = new FormUrlEncodedContent(new[]
        {
            new KeyValuePair<string, string>("grant_type", "password"),
            new KeyValuePair<string, string>("client_id", "postman_client"),
            new KeyValuePair<string, string>("client_secret", "postman_secret"),
            new KeyValuePair<string, string>("username", testUser.UserName!),
            new KeyValuePair<string, string>("password", "Test123!"),
            new KeyValuePair<string, string>("scope", "openid") // Only openid scope
        });

        var tokenResponse = await _client.PostAsync("/connect/token", tokenRequest);
        tokenResponse.EnsureSuccessStatusCode();

        var tokenContent = await tokenResponse.Content.ReadAsStringAsync();
        var tokenData = JsonSerializer.Deserialize<Dictionary<string, object>>(tokenContent);
        var accessToken = tokenData!["access_token"].ToString();

        // Act - Call UserInfo endpoint
        var userInfoRequest = new HttpRequestMessage(HttpMethod.Get, "/connect/userinfo");
        userInfoRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

        var userInfoResponse = await _client.SendAsync(userInfoRequest);

        // Assert
        userInfoResponse.EnsureSuccessStatusCode();

        var userInfoContent = await userInfoResponse.Content.ReadAsStringAsync();
        var userInfo = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(userInfoContent);

        // Should only contain subject claim from openid scope
        Assert.True(userInfo!.ContainsKey("sub"));
        Assert.Equal(testUser.Id, userInfo["sub"].GetString());

        // Should NOT contain email or profile claims since those scopes weren't requested
        Assert.False(userInfo.ContainsKey("email"));
        Assert.False(userInfo.ContainsKey("name"));
        Assert.False(userInfo.ContainsKey("phone_number"));
    }

    [Fact]
    public async Task UserInfo_WithRolesScope_ReturnsUserRoles()
    {
        // Arrange
        using var scope = _factory.Services.CreateScope();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<IdentityUser>>();
        var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();

        // Create test roles
        var adminRole = new IdentityRole("Administrator");
        var userRole = new IdentityRole("User");
        
        await roleManager.CreateAsync(adminRole);
        await roleManager.CreateAsync(userRole);

        // Create a test user
        var testUser = new IdentityUser
        {
            UserName = "roleuser@example.com",
            Email = "roleuser@example.com",
            EmailConfirmed = true
        };

        var userResult = await userManager.CreateAsync(testUser, "Test123!");
        Assert.True(userResult.Succeeded);

        // Assign roles to user
        await userManager.AddToRoleAsync(testUser, "Administrator");
        await userManager.AddToRoleAsync(testUser, "User");

        // Get an access token with roles scope
        var tokenRequest = new FormUrlEncodedContent(new[]
        {
            new KeyValuePair<string, string>("grant_type", "password"),
            new KeyValuePair<string, string>("client_id", "postman_client"),
            new KeyValuePair<string, string>("client_secret", "postman_secret"),
            new KeyValuePair<string, string>("username", testUser.UserName!),
            new KeyValuePair<string, string>("password", "Test123!"),
            new KeyValuePair<string, string>("scope", "openid roles")
        });

        var tokenResponse = await _client.PostAsync("/connect/token", tokenRequest);
        tokenResponse.EnsureSuccessStatusCode();

        var tokenContent = await tokenResponse.Content.ReadAsStringAsync();
        var tokenData = JsonSerializer.Deserialize<Dictionary<string, object>>(tokenContent);
        var accessToken = tokenData!["access_token"].ToString();

        // Act - Call UserInfo endpoint
        var userInfoRequest = new HttpRequestMessage(HttpMethod.Get, "/connect/userinfo");
        userInfoRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

        var userInfoResponse = await _client.SendAsync(userInfoRequest);

        // Assert
        userInfoResponse.EnsureSuccessStatusCode();

        var userInfoContent = await userInfoResponse.Content.ReadAsStringAsync();
        var userInfo = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(userInfoContent);

        // Verify basic claims
        Assert.True(userInfo!.ContainsKey("sub"));
        Assert.Equal(testUser.Id, userInfo["sub"].GetString());

        // Verify roles are included
        Assert.True(userInfo.ContainsKey("role"));
        var roles = userInfo["role"].EnumerateArray().Select(r => r.GetString()).ToArray();
        Assert.Contains("Administrator", roles);
        Assert.Contains("User", roles);
        Assert.Equal(2, roles.Length);
    }
}