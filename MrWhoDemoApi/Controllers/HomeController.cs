using Microsoft.AspNetCore.Mvc;

namespace MrWhoDemoApi.Controllers
{
    [ApiController]
    [Route("/")]
    public class HomeController : Controller
    {
        public IActionResult Index()
        {
            return Content("MrWhoDemoApi is running. Navigate to /WeatherForecast to see the weather forecast.");
        }
    }
}
