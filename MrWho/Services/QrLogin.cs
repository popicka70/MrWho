using System.Collections.Concurrent;
using MrWho.Shared;

namespace MrWho.Services;

public sealed class QrLoginTicket
{
    public required string Token { get; init; }
    public DateTimeOffset ExpiresAt { get; init; }
    public string? ReturnUrl { get; init; }
    public string? ClientId { get; init; }
    public string? ApprovedUserId { get; set; }
    public bool Completed { get; set; }
}

public interface IQrLoginStore
{
    QrLoginTicket Create(string? returnUrl, string? clientId, TimeSpan? ttl = null);
    QrLoginTicket? Get(string token);
    bool Approve(string token, string userId);
    bool Complete(string token);
}

/// <summary>
/// Enhanced QR login store that supports both session-based and persistent QR codes
/// </summary>
public interface IEnhancedQrLoginService
{
    // Session-based QR (original implementation)
    QrLoginTicket CreateSessionQr(string? returnUrl, string? clientId, TimeSpan? ttl = null);
    QrLoginTicket? GetSessionQr(string token);
    bool ApproveSessionQr(string token, string userId);
    bool CompleteSessionQr(string token);

    // Persistent QR (new implementation)
    Task<string> CreatePersistentQrAsync(string? userId, string? clientId, string? returnUrl, TimeSpan? ttl = null);
    Task<Models.PersistentQrSession?> GetPersistentQrAsync(string token);
    Task<bool> ApprovePersistentQrAsync(string token, string userId, string deviceId);
    Task<bool> RejectPersistentQrAsync(string token, string userId, string deviceId);
    Task<bool> CompletePersistentQrAsync(string token);

    // Unified interface
    Task<QrSessionInfo> GetQrSessionInfoAsync(string token);
    Task<bool> ApproveQrAsync(string token, string userId, string? deviceId = null);
    Task<bool> CompleteQrAsync(string token);
}

public class EnhancedQrLoginService : IEnhancedQrLoginService
{
    private readonly IQrLoginStore _sessionStore;
    private readonly IDeviceManagementService _deviceService;
    private readonly ILogger<EnhancedQrLoginService> _logger;

    public EnhancedQrLoginService(
        IQrLoginStore sessionStore,
        IDeviceManagementService deviceService,
        ILogger<EnhancedQrLoginService> logger)
    {
        _sessionStore = sessionStore;
        _deviceService = deviceService;
        _logger = logger;
    }

    // ============================================================================
    // SESSION-BASED QR (ORIGINAL IMPLEMENTATION)
    // ============================================================================

    public QrLoginTicket CreateSessionQr(string? returnUrl, string? clientId, TimeSpan? ttl = null)
    {
        var ticket = _sessionStore.Create(returnUrl, clientId, ttl);
        _logger.LogDebug("Created session-based QR ticket {Token} for client {ClientId}", ticket.Token, clientId);
        return ticket;
    }

    public QrLoginTicket? GetSessionQr(string token)
    {
        return _sessionStore.Get(token);
    }

    public bool ApproveSessionQr(string token, string userId)
    {
        var result = _sessionStore.Approve(token, userId);
        if (result)
        {
            _logger.LogDebug("Session-based QR {Token} approved by user {UserId}", token, userId);
        }
        return result;
    }

    public bool CompleteSessionQr(string token)
    {
        var result = _sessionStore.Complete(token);
        if (result)
        {
            _logger.LogDebug("Session-based QR {Token} completed", token);
        }
        return result;
    }

    // ============================================================================
    // PERSISTENT QR (NEW IMPLEMENTATION)
    // ============================================================================

    public async Task<string> CreatePersistentQrAsync(string? userId, string? clientId, string? returnUrl, TimeSpan? ttl = null)
    {
        var request = new CreateQrSessionRequest
        {
            UserId = userId,
            ClientId = clientId,
            ReturnUrl = returnUrl,
            ExpirationDuration = ttl ?? TimeSpan.FromMinutes(5)
        };

        var session = await _deviceService.CreateQrSessionAsync(request);
        _logger.LogDebug("Created persistent QR session {SessionId} (token: {Token}) for client {ClientId}", 
            session.Id, session.Token, clientId);
        return session.Token;
    }

    public async Task<Models.PersistentQrSession?> GetPersistentQrAsync(string token)
    {
        return await _deviceService.GetQrSessionAsync(token);
    }

    public async Task<bool> ApprovePersistentQrAsync(string token, string userId, string deviceId)
    {
        var result = await _deviceService.ApproveQrSessionAsync(token, userId, deviceId);
        if (result)
        {
            _logger.LogDebug("Persistent QR {Token} approved by user {UserId} device {DeviceId}", token, userId, deviceId);
        }
        return result;
    }

    public async Task<bool> RejectPersistentQrAsync(string token, string userId, string deviceId)
    {
        var result = await _deviceService.RejectQrSessionAsync(token, userId, deviceId);
        if (result)
        {
            _logger.LogDebug("Persistent QR {Token} rejected by user {UserId} device {DeviceId}", token, userId, deviceId);
        }
        return result;
    }

    public async Task<bool> CompletePersistentQrAsync(string token)
    {
        var result = await _deviceService.CompleteQrSessionAsync(token);
        if (result)
        {
            _logger.LogDebug("Persistent QR {Token} completed", token);
        }
        return result;
    }

    // ============================================================================
    // UNIFIED INTERFACE
    // ============================================================================

    public async Task<QrSessionInfo> GetQrSessionInfoAsync(string token)
    {
        // First check if it's a persistent QR session
        var persistentSession = await GetPersistentQrAsync(token);
        if (persistentSession != null)
        {
            return new QrSessionInfo
            {
                Token = token,
                Type = QrSessionType.Persistent,
                Status = MapPersistentStatus(persistentSession.Status),
                UserId = persistentSession.UserId,
                ClientId = persistentSession.ClientId,
                ReturnUrl = persistentSession.ReturnUrl,
                ExpiresAt = persistentSession.ExpiresAt,
                ApprovedAt = persistentSession.ApprovedAt,
                DeviceId = persistentSession.ApprovedByDevice?.DeviceId,
                DeviceName = persistentSession.ApprovedByDevice?.DeviceName
            };
        }

        // Check if it's a session-based QR
        var sessionTicket = GetSessionQr(token);
        if (sessionTicket != null)
        {
            return new QrSessionInfo
            {
                Token = token,
                Type = QrSessionType.Session,
                Status = MapSessionStatus(sessionTicket),
                UserId = sessionTicket.ApprovedUserId,
                ClientId = sessionTicket.ClientId,
                ReturnUrl = sessionTicket.ReturnUrl,
                ExpiresAt = sessionTicket.ExpiresAt.UtcDateTime,
                ApprovedAt = !string.IsNullOrEmpty(sessionTicket.ApprovedUserId) ? DateTime.UtcNow : null
            };
        }

        throw new ArgumentException($"QR session with token {token} not found or expired", nameof(token));
    }

    public async Task<bool> ApproveQrAsync(string token, string userId, string? deviceId = null)
    {
        // Try persistent QR first
        if (!string.IsNullOrEmpty(deviceId))
        {
            var persistentResult = await ApprovePersistentQrAsync(token, userId, deviceId);
            if (persistentResult)
                return true;
        }

        // Fallback to session-based QR
        return ApproveSessionQr(token, userId);
    }

    public async Task<bool> CompleteQrAsync(string token)
    {
        // Try persistent QR first
        var persistentResult = await CompletePersistentQrAsync(token);
        if (persistentResult)
            return true;

        // Fallback to session-based QR
        return CompleteSessionQr(token);
    }

    // ============================================================================
    // HELPER METHODS
    // ============================================================================

    private static QrSessionStatusEnum MapPersistentStatus(QrSessionStatus persistentStatus)
    {
        return persistentStatus switch
        {
            QrSessionStatus.Pending => QrSessionStatusEnum.Pending,
            QrSessionStatus.Approved => QrSessionStatusEnum.Approved,
            QrSessionStatus.Completed => QrSessionStatusEnum.Completed,
            QrSessionStatus.Expired => QrSessionStatusEnum.Expired,
            QrSessionStatus.Rejected => QrSessionStatusEnum.Rejected,
            QrSessionStatus.Failed => QrSessionStatusEnum.Failed,
            _ => QrSessionStatusEnum.Failed
        };
    }

    private static QrSessionStatusEnum MapSessionStatus(QrLoginTicket sessionTicket)
    {
        if (sessionTicket.Completed)
            return QrSessionStatusEnum.Completed;
        
        if (!string.IsNullOrEmpty(sessionTicket.ApprovedUserId))
            return QrSessionStatusEnum.Approved;
        
        return QrSessionStatusEnum.Pending;
    }
}

public sealed class InMemoryQrLoginStore : IQrLoginStore
{
    private readonly ConcurrentDictionary<string, QrLoginTicket> _tickets = new();
    private static string NewToken() => Convert.ToBase64String(Guid.NewGuid().ToByteArray())
        .Replace("+", "-").Replace("/", "_").TrimEnd('=');

    public QrLoginTicket Create(string? returnUrl, string? clientId, TimeSpan? ttl = null)
    {
        var token = NewToken();
        var ticket = new QrLoginTicket
        {
            Token = token,
            ExpiresAt = DateTimeOffset.UtcNow.Add(ttl ?? TimeSpan.FromMinutes(3)),
            ReturnUrl = returnUrl,
            ClientId = clientId
        };
        _tickets[token] = ticket;
        return ticket;
    }

    public QrLoginTicket? Get(string token)
    {
        if (_tickets.TryGetValue(token, out var t))
        {
            if (t.ExpiresAt <= DateTimeOffset.UtcNow || t.Completed)
            {
                _tickets.TryRemove(token, out _);
                return null;
            }
            return t;
        }
        return null;
    }

    public bool Approve(string token, string userId)
    {
        var t = Get(token);
        if (t is null) return false;
        t.ApprovedUserId = userId;
        return true;
    }

    public bool Complete(string token)
    {
        if (_tickets.TryGetValue(token, out var t))
        {
            t.Completed = true;
            _tickets.TryRemove(token, out _);
            return true;
        }
        return false;
    }
}

// ============================================================================
// SUPPORTING TYPES
// ============================================================================

public enum QrSessionType
{
    Session,    // In-memory session-based QR (original)
    Persistent  // Database-backed persistent QR (new)
}

public enum QrSessionStatusEnum
{
    Pending,
    Approved,
    Completed,
    Expired,
    Rejected,
    Failed
}

public class QrSessionInfo
{
    public required string Token { get; set; }
    public required QrSessionType Type { get; set; }
    public required QrSessionStatusEnum Status { get; set; }
    public string? UserId { get; set; }
    public string? ClientId { get; set; }
    public string? ReturnUrl { get; set; }
    public DateTime ExpiresAt { get; set; }
    public DateTime? ApprovedAt { get; set; }
    public string? DeviceId { get; set; }
    public string? DeviceName { get; set; }
}
