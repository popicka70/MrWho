using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using MrWho.Handlers;
using MrWho.Services.Mediator;

namespace MrWho.Endpoints;

public sealed record UserInfoRequest(HttpContext HttpContext) : IRequest<IResult>;

public sealed class UserInfoHandler : IRequestHandler<UserInfoRequest, IResult>
{
    private readonly IUserInfoHandler _userInfoHandler;

    public UserInfoHandler(IUserInfoHandler userInfoHandler) => _userInfoHandler = userInfoHandler;

    public Task<IResult> Handle(UserInfoRequest request, CancellationToken cancellationToken)
        => _userInfoHandler.HandleUserInfoRequestAsync(request.HttpContext);
}
