using Microsoft.AspNetCore.Mvc;
using MrWho.Services.Mediator;

namespace MrWho.Handlers.Auth;

public sealed class RegisterSuccessGetHandler : IRequestHandler<MrWho.Endpoints.Auth.RegisterSuccessGetRequest, IActionResult>
{
    public Task<IActionResult> Handle(MrWho.Endpoints.Auth.RegisterSuccessGetRequest request, CancellationToken cancellationToken)
    {
        return Task.FromResult<IActionResult>(new ViewResult { ViewName = "RegisterSuccess" });
    }
}
