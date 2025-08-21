using Microsoft.AspNetCore.Http;
using MrWho.Services.Mediator;

namespace MrWho.Endpoints;

public sealed record OidcLogoutRequest(HttpContext HttpContext) : IRequest<IResult>;
