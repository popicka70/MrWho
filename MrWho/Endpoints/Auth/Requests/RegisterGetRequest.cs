using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using MrWho.Services.Mediator;

namespace MrWho.Endpoints.Auth;

public sealed record RegisterGetRequest(HttpContext HttpContext) : IRequest<IActionResult>;
