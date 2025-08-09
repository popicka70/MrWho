using System.Threading;
using System.Threading.Tasks;

namespace MrWho.Services.Mediator;

public interface IMediator
{
    Task<TResponse> Send<TResponse>(IRequest<TResponse> request, CancellationToken cancellationToken = default);
}
