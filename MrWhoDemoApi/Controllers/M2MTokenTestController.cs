using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Net.Http.Headers;
using System.Text.Json;

namespace MrWhoDemoApi.Controllers;

[ApiController]
[Route("m2m-test")] // Simple demo endpoint to show machine-to-machine call
public class M2MTokenTestController : ControllerBase
{
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly ILogger<M2MTokenTestController> _logger;

    public M2MTokenTestController(IHttpClientFactory httpClientFactory, ILogger<M2MTokenTestController> logger)
    {
        _httpClientFactory = httpClientFactory;
        _logger = logger;
    }

    [HttpGet("obtain-token-and-call" )]
    public async Task<IActionResult> GetViaClientCredentials()
    {
        // This demonstrates obtaining a token with client credentials INSIDE the API (for demo only).
        // In real scenarios, another service would obtain the token and call this API.
        var clientId = "mrwho_demo_api_client";
        var clientSecret = "DemoApiClientSecret2025!";
        var tokenEndpoint = "https://localhost:7113/connect/token";

        var http = _httpClientFactory.CreateClient();
        var form = new Dictionary<string, string>
        {
            ["grant_type"] = "client_credentials",
            ["client_id"] = clientId,
            ["client_secret"] = clientSecret,
            ["scope"] = "api.read"
        };

        using var tokenResponse = await http.PostAsync(tokenEndpoint, new FormUrlEncodedContent(form));
        var tokenJson = await tokenResponse.Content.ReadAsStringAsync();
        if (!tokenResponse.IsSuccessStatusCode)
        {
            return StatusCode((int)tokenResponse.StatusCode, new { error = "token_request_failed", details = tokenJson });
        }

        using var doc = JsonDocument.Parse(tokenJson);
        var accessToken = doc.RootElement.GetProperty("access_token").GetString();
        if (string.IsNullOrEmpty(accessToken))
        {
            return BadRequest(new { error = "no_access_token" });
        }

        // Call the protected WeatherForecast endpoint with this token
        var apiClient = _httpClientFactory.CreateClient();
        apiClient.BaseAddress = new Uri("https://localhost:7162/");
        apiClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        var forecastResponse = await apiClient.GetAsync("WeatherForecast");
        var forecastContent = await forecastResponse.Content.ReadAsStringAsync();

        return Ok(new
        {
            token_acquired = true,
            token_length = accessToken.Length,
            weather_status = (int)forecastResponse.StatusCode,
            weather_ok = forecastResponse.IsSuccessStatusCode,
            weather_raw = forecastContent
        });
    }
}
