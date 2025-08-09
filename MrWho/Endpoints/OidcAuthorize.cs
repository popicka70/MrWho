using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using MrWho.Services.Mediator;
using MrWho.Handlers;

namespace MrWho.Endpoints;

public sealed record OidcAuthorizeRequest(HttpContext HttpContext) : IRequest<IResult>;

public sealed class OidcAuthorizeHandler : IRequestHandler<OidcAuthorizeRequest, IResult>
{
    private readonly IOidcAuthorizationHandler _authorizationHandler;

    public OidcAuthorizeHandler(IOidcAuthorizationHandler authorizationHandler)
        => _authorizationHandler = authorizationHandler;

    public Task<IResult> Handle(OidcAuthorizeRequest request, CancellationToken cancellationToken)
        => _authorizationHandler.HandleAuthorizationRequestAsync(request.HttpContext);
}
