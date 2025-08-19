using Microsoft.AspNetCore.Mvc;
using MrWho.Services.Mediator;

namespace MrWho.Endpoints.Auth;

public sealed class RegisterSuccessGetHandler : IRequestHandler<RegisterSuccessGetRequest, IActionResult>
{
    public Task<IActionResult> Handle(RegisterSuccessGetRequest request, CancellationToken cancellationToken)
    {
        return Task.FromResult<IActionResult>(new ViewResult { ViewName = "RegisterSuccess" });
    }
}
