using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using MrWho.Services.Mediator;

namespace MrWho.Endpoints.Auth;

public sealed record LoginGetRequest(HttpContext HttpContext, string? ReturnUrl, string? ClientId, string? Mode) : IRequest<IActionResult>;
