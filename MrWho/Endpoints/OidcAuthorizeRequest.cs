using Microsoft.AspNetCore.Http;
using MrWho.Services.Mediator;

namespace MrWho.Endpoints;

public sealed record OidcAuthorizeRequest(HttpContext HttpContext) : IRequest<IResult>;
