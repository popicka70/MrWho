using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using MrWho.Services.Mediator;
using MrWho.Handlers;

namespace MrWho.Handlers.Oidc;

public sealed class OidcAuthorizeHandler : IRequestHandler<MrWho.Endpoints.OidcAuthorizeRequest, IResult>
{
    private readonly IOidcAuthorizationHandler _authorizationHandler;

    public OidcAuthorizeHandler(IOidcAuthorizationHandler authorizationHandler)
        => _authorizationHandler = authorizationHandler;

    public Task<IResult> Handle(MrWho.Endpoints.OidcAuthorizeRequest request, CancellationToken cancellationToken)
        => _authorizationHandler.HandleAuthorizationRequestAsync(request.HttpContext);
}
