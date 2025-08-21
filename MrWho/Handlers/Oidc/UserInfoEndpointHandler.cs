using System.Threading;
using System.Threading.Tasks;
using MrWho.Services.Mediator;

namespace MrWho.Handlers.Oidc;

public sealed class UserInfoEndpointHandler : IRequestHandler<MrWho.Endpoints.UserInfoRequest, IResult>
{
    private readonly MrWho.Handlers.IUserInfoHandler _userInfoHandler;

    public UserInfoEndpointHandler(MrWho.Handlers.IUserInfoHandler userInfoHandler) => _userInfoHandler = userInfoHandler;

    public Task<IResult> Handle(MrWho.Endpoints.UserInfoRequest request, CancellationToken cancellationToken)
        => _userInfoHandler.HandleUserInfoRequestAsync(request.HttpContext);
}
