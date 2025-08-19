using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using MrWho.Services.Mediator;

namespace MrWho.Endpoints.Auth;

public sealed record ProcessLogoutRequest(HttpContext HttpContext, string? ClientId, string? PostLogoutRedirectUri) : IRequest<IActionResult>;
