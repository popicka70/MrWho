using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;

namespace MrWho.Services.Mediator;

// Lightweight in-project mediator to avoid external dependency
public sealed class Mediator : IMediator
{
    private readonly IServiceProvider _services;

    public Mediator(IServiceProvider services)
    {
        _services = services;
    }

    public Task<TResponse> Send<TResponse>(IRequest<TResponse> request, CancellationToken cancellationToken = default)
    {
        if (request is null) throw new ArgumentNullException(nameof(request));

        var handlerType = typeof(IRequestHandler<,>).MakeGenericType(request.GetType(), typeof(TResponse));
        var handler = _services.GetService(handlerType);
        if (handler is null)
        {
            throw new InvalidOperationException($"No handler registered for {request.GetType().Name}");
        }

        var method = handlerType.GetMethod("Handle");
        if (method is null)
        {
            throw new InvalidOperationException($"Handler for {request.GetType().Name} does not implement Handle method");
        }

        return (Task<TResponse>)method.Invoke(handler, new object[] { request, cancellationToken })!;
    }
}
