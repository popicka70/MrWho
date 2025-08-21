using Microsoft.AspNetCore.Http;
using MrWho.Services.Mediator;

namespace MrWho.Endpoints;

public sealed record UserInfoRequest(HttpContext HttpContext) : IRequest<IResult>;
