using Microsoft.AspNetCore.Http;
using MrWho.Services.Mediator;

namespace MrWho.Endpoints;

public sealed record OidcTokenRequest(HttpContext HttpContext) : IRequest<IResult>;
