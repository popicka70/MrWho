using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace MrWhoDemoApi.Controllers;

[ApiController]
[Route("[controller]")]
[Authorize(Policy = "ApiRead")] // Require api.read scope
public class WeatherForecastController : ControllerBase
{
    private static readonly string[] Summaries = new[]
    {
        "Freezing", "Bracing", "Chilly", "Cool", "Mild", "Warm", "Balmy", "Hot", "Sweltering", "Scorching"
    };

    private readonly ILogger<WeatherForecastController> _logger;

    public WeatherForecastController(ILogger<WeatherForecastController> logger)
    {
        _logger = logger;
    }

    [HttpGet(Name = "GetWeatherForecast")]
    public IEnumerable<WeatherForecast> Get()
    {
        var subject = User.FindFirst("sub")?.Value ?? "anonymous";
        var scopes = string.Join(' ', User.FindAll("scope").Select(c => c.Value).Concat(User.FindAll("scp").Select(c => c.Value)));
        _logger.LogInformation("Weather forecast requested by sub={Sub} scopes={Scopes}", subject, scopes);

        return Enumerable.Range(1, 5).Select(index => new WeatherForecast
        {
            Date = DateOnly.FromDateTime(DateTime.Now.AddDays(index)),
            TemperatureC = Random.Shared.Next(-20, 55),
            Summary = Summaries[Random.Shared.Next(Summaries.Length)]
        })
        .ToArray();
    }
}
