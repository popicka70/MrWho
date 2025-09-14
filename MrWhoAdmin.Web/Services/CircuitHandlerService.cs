using Microsoft.AspNetCore.Components.Server.Circuits;

namespace MrWhoAdmin.Web.Services;

/// <summary>
/// Circuit handler for managing Blazor Server circuit lifecycle and preventing authentication-related disposal issues
/// </summary>
public class CircuitHandlerService : CircuitHandler
{
    private readonly ILogger<CircuitHandlerService> _logger;

    public CircuitHandlerService(ILogger<CircuitHandlerService> logger)
    {
        _logger = logger;
    }

    public override Task OnCircuitOpenedAsync(Circuit circuit, CancellationToken cancellationToken)
    {
        _logger.LogDebug("Circuit {CircuitId} opened", circuit.Id);
        return Task.CompletedTask;
    }

    public override Task OnCircuitClosedAsync(Circuit circuit, CancellationToken cancellationToken)
    {
        _logger.LogDebug("Circuit {CircuitId} closed", circuit.Id);
        return Task.CompletedTask;
    }

    public override Task OnConnectionDownAsync(Circuit circuit, CancellationToken cancellationToken)
    {
        _logger.LogDebug("Circuit {CircuitId} connection down", circuit.Id);
        return Task.CompletedTask;
    }

    public override Task OnConnectionUpAsync(Circuit circuit, CancellationToken cancellationToken)
    {
        _logger.LogDebug("Circuit {CircuitId} connection up", circuit.Id);
        return Task.CompletedTask;
    }
}
