using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using MrWho.Services.Mediator;

namespace MrWho.Endpoints.Auth;

public sealed record LoginPostRequest(HttpContext HttpContext, MrWho.Controllers.LoginViewModel Model, string? ReturnUrl, string? ClientId) : IRequest<IActionResult>;
