using Microsoft.AspNetCore.Mvc;

namespace MrWho.Controllers;

public class HomeController : Controller
{
    public IActionResult Index()
    {
        return View();
    }
}
