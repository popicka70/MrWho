using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using MrWho.Handlers;
using MrWho.Services.Mediator;

namespace MrWho.Handlers.Oidc;

public sealed class OidcTokenHandler : IRequestHandler<MrWho.Endpoints.OidcTokenRequest, IResult>
{
    private readonly ITokenHandler _tokenHandler;

    public OidcTokenHandler(ITokenHandler tokenHandler) => _tokenHandler = tokenHandler;

    public Task<IResult> Handle(MrWho.Endpoints.OidcTokenRequest request, CancellationToken cancellationToken)
        => _tokenHandler.HandleTokenRequestAsync(request.HttpContext);
}
