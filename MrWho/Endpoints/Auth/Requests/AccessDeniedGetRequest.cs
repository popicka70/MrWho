using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using MrWho.Services.Mediator;

namespace MrWho.Endpoints.Auth;

public sealed record AccessDeniedGetRequest(HttpContext HttpContext, string? ReturnUrl, string? ClientId) : IRequest<IActionResult>;
