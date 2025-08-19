using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using MrWho.Services.Mediator;
using MrWho.Shared.Models;

namespace MrWho.Endpoints.Auth;

public sealed record RegisterPostRequest(HttpContext HttpContext, RegisterUserRequest Input) : IRequest<IActionResult>;
