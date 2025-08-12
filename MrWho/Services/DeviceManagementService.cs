using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using MrWho.Data;
using MrWho.Models;
using MrWho.Shared;
using System.Text.Json;

namespace MrWho.Services;

/// <summary>
/// Service for managing user device registration and persistent QR code sessions
/// </summary>
public interface IDeviceManagementService
{
    // Device Registration
    Task<UserDevice> RegisterDeviceAsync(string userId, RegisterDeviceRequest request);
    Task<UserDevice?> GetDeviceAsync(string userId, string deviceId);
    Task<UserDevice?> GetDeviceByIdAsync(string id);
    Task<List<UserDevice>> GetUserDevicesAsync(string userId, bool activeOnly = true);
    Task<bool> UpdateDeviceAsync(string deviceId, UpdateDeviceRequest request);
    Task<bool> RevokeDeviceAsync(string userId, string deviceId);
    Task<bool> SetDeviceTrustedAsync(string userId, string deviceId, bool trusted);

    // Persistent QR Sessions
    Task<PersistentQrSession> CreateQrSessionAsync(CreateQrSessionRequest request);
    Task<PersistentQrSession?> GetQrSessionAsync(string token);
    Task<bool> ApproveQrSessionAsync(string token, string userId, string deviceId);
    Task<bool> RejectQrSessionAsync(string token, string userId, string deviceId);
    Task<bool> CompleteQrSessionAsync(string token);
    Task CleanupExpiredQrSessionsAsync();

    // Device Authentication Logging
    Task LogDeviceActivityAsync(string deviceId, string userId, DeviceAuthActivity activity, 
        string? clientId = null, bool isSuccessful = true, string? errorMessage = null, 
        string? ipAddress = null, string? userAgent = null, object? metadata = null);

    // Security & Monitoring
    Task<List<DeviceAuthenticationLog>> GetDeviceActivityAsync(string deviceId, int count = 50);
    Task<List<DeviceAuthenticationLog>> GetUserDeviceActivityAsync(string userId, int count = 100);
    Task<bool> IsDeviceCompromisedAsync(string deviceId);
    Task MarkDeviceCompromisedAsync(string deviceId, string reason);
}

public class DeviceManagementService : IDeviceManagementService
{
    private readonly ApplicationDbContext _context;
    private readonly UserManager<IdentityUser> _userManager;
    private readonly ILogger<DeviceManagementService> _logger;

    public DeviceManagementService(
        ApplicationDbContext context,
        UserManager<IdentityUser> userManager,
        ILogger<DeviceManagementService> logger)
    {
        _context = context;
        _userManager = userManager;
        _logger = logger;
    }

    // ============================================================================
    // DEVICE REGISTRATION
    // ============================================================================

    public async Task<UserDevice> RegisterDeviceAsync(string userId, RegisterDeviceRequest request)
    {
        var user = await _userManager.FindByIdAsync(userId);
        if (user == null)
            throw new ArgumentException($"User {userId} not found", nameof(userId));

        // Check if device already exists
        var existingDevice = await _context.UserDevices
            .FirstOrDefaultAsync(d => d.UserId == userId && d.DeviceId == request.DeviceId);

        if (existingDevice != null)
        {
            // Update existing device
            existingDevice.DeviceName = request.DeviceName;
            existingDevice.DeviceType = request.DeviceType;
            existingDevice.OperatingSystem = request.OperatingSystem;
            existingDevice.UserAgent = request.UserAgent;
            existingDevice.PushToken = request.PushToken;
            existingDevice.PublicKey = request.PublicKey;
            existingDevice.IsActive = true;
            existingDevice.UpdatedAt = DateTime.UtcNow;
            existingDevice.LastIpAddress = request.IpAddress;
            existingDevice.Metadata = request.Metadata != null ? JsonSerializer.Serialize(request.Metadata) : null;

            await _context.SaveChangesAsync();

            await LogDeviceActivityAsync(existingDevice.Id, userId, DeviceAuthActivity.DeviceUpdated, 
                ipAddress: request.IpAddress, userAgent: request.UserAgent);

            _logger.LogInformation("Updated existing device {DeviceId} for user {UserId}", request.DeviceId, userId);
            return existingDevice;
        }

        // Create new device
        var device = new UserDevice
        {
            UserId = userId,
            DeviceId = request.DeviceId,
            DeviceName = request.DeviceName,
            DeviceType = request.DeviceType,
            OperatingSystem = request.OperatingSystem,
            UserAgent = request.UserAgent,
            IsTrusted = request.IsTrusted,
            CanApproveLogins = request.CanApproveLogins,
            PushToken = request.PushToken,
            PublicKey = request.PublicKey,
            LastIpAddress = request.IpAddress,
            ExpiresAt = request.ExpiresAt,
            Metadata = request.Metadata != null ? JsonSerializer.Serialize(request.Metadata) : null
        };

        _context.UserDevices.Add(device);
        await _context.SaveChangesAsync();

        await LogDeviceActivityAsync(device.Id, userId, DeviceAuthActivity.DeviceRegistered, 
            ipAddress: request.IpAddress, userAgent: request.UserAgent);

        _logger.LogInformation("Registered new device {DeviceId} ({DeviceName}) for user {UserId}", 
            request.DeviceId, request.DeviceName, userId);

        return device;
    }

    public async Task<UserDevice?> GetDeviceAsync(string userId, string deviceId)
    {
        return await _context.UserDevices
            .Include(d => d.User)
            .FirstOrDefaultAsync(d => d.UserId == userId && d.DeviceId == deviceId && d.IsActive);
    }

    public async Task<UserDevice?> GetDeviceByIdAsync(string id)
    {
        return await _context.UserDevices
            .Include(d => d.User)
            .FirstOrDefaultAsync(d => d.Id == id);
    }

    public async Task<List<UserDevice>> GetUserDevicesAsync(string userId, bool activeOnly = true)
    {
        var query = _context.UserDevices
            .Where(d => d.UserId == userId);

        if (activeOnly)
            query = query.Where(d => d.IsActive);

        return await query
            .OrderByDescending(d => d.LastUsedAt ?? d.CreatedAt)
            .ToListAsync();
    }

    public async Task<bool> UpdateDeviceAsync(string deviceId, UpdateDeviceRequest request)
    {
        var device = await _context.UserDevices
            .FirstOrDefaultAsync(d => d.DeviceId == deviceId && d.IsActive);

        if (device == null)
            return false;

        if (!string.IsNullOrEmpty(request.DeviceName))
            device.DeviceName = request.DeviceName;
        
        if (request.DeviceType.HasValue)
            device.DeviceType = request.DeviceType.Value;
        
        if (!string.IsNullOrEmpty(request.OperatingSystem))
            device.OperatingSystem = request.OperatingSystem;
        
        if (!string.IsNullOrEmpty(request.UserAgent))
            device.UserAgent = request.UserAgent;
        
        if (!string.IsNullOrEmpty(request.PushToken))
            device.PushToken = request.PushToken;
        
        if (!string.IsNullOrEmpty(request.PublicKey))
            device.PublicKey = request.PublicKey;
        
        if (request.CanApproveLogins.HasValue)
            device.CanApproveLogins = request.CanApproveLogins.Value;
        
        if (request.ExpiresAt.HasValue)
            device.ExpiresAt = request.ExpiresAt.Value;
        
        if (request.Metadata != null)
            device.Metadata = JsonSerializer.Serialize(request.Metadata);

        device.UpdatedAt = DateTime.UtcNow;

        await _context.SaveChangesAsync();

        await LogDeviceActivityAsync(device.Id, device.UserId, DeviceAuthActivity.DeviceUpdated);

        _logger.LogInformation("Updated device {DeviceId} for user {UserId}", deviceId, device.UserId);
        return true;
    }

    public async Task<bool> RevokeDeviceAsync(string userId, string deviceId)
    {
        var device = await _context.UserDevices
            .FirstOrDefaultAsync(d => d.UserId == userId && d.DeviceId == deviceId);

        if (device == null)
            return false;

        device.IsActive = false;
        device.UpdatedAt = DateTime.UtcNow;

        await _context.SaveChangesAsync();

        await LogDeviceActivityAsync(device.Id, userId, DeviceAuthActivity.DeviceRevoked);

        _logger.LogInformation("Revoked device {DeviceId} for user {UserId}", deviceId, userId);
        return true;
    }

    public async Task<bool> SetDeviceTrustedAsync(string userId, string deviceId, bool trusted)
    {
        var device = await _context.UserDevices
            .FirstOrDefaultAsync(d => d.UserId == userId && d.DeviceId == deviceId && d.IsActive);

        if (device == null)
            return false;

        device.IsTrusted = trusted;
        device.UpdatedAt = DateTime.UtcNow;

        await _context.SaveChangesAsync();

        await LogDeviceActivityAsync(device.Id, userId, DeviceAuthActivity.DeviceUpdated, 
            metadata: new { TrustedChanged = true, NewTrustedValue = trusted });

        _logger.LogInformation("Set device {DeviceId} trusted status to {Trusted} for user {UserId}", 
            deviceId, trusted, userId);
        return true;
    }

    // ============================================================================
    // PERSISTENT QR SESSIONS
    // ============================================================================

    public async Task<PersistentQrSession> CreateQrSessionAsync(CreateQrSessionRequest request)
    {
        var session = new PersistentQrSession
        {
            Token = GenerateSecureToken(),
            UserId = request.UserId,
            ClientId = request.ClientId,
            ReturnUrl = request.ReturnUrl,
            ExpiresAt = DateTime.UtcNow.Add(request.ExpirationDuration ?? TimeSpan.FromMinutes(5)),
            InitiatorIpAddress = request.IpAddress,
            Metadata = request.Metadata != null ? JsonSerializer.Serialize(request.Metadata) : null
        };

        _context.PersistentQrSessions.Add(session);
        await _context.SaveChangesAsync();

        _logger.LogInformation("Created QR session {SessionId} (token: {Token}) for client {ClientId}", 
            session.Id, session.Token, request.ClientId);

        return session;
    }

    public async Task<PersistentQrSession?> GetQrSessionAsync(string token)
    {
        return await _context.PersistentQrSessions
            .Include(q => q.User)
            .Include(q => q.ApprovedByDevice)
            .FirstOrDefaultAsync(q => q.Token == token && q.ExpiresAt > DateTime.UtcNow);
    }

    public async Task<bool> ApproveQrSessionAsync(string token, string userId, string deviceId)
    {
        var session = await _context.PersistentQrSessions
            .FirstOrDefaultAsync(q => q.Token == token && q.Status == QrSessionStatus.Pending && q.ExpiresAt > DateTime.UtcNow);

        if (session == null)
            return false;

        var device = await _context.UserDevices
            .FirstOrDefaultAsync(d => d.UserId == userId && d.DeviceId == deviceId && d.IsActive && d.CanApproveLogins);

        if (device == null)
            return false;

        session.UserId = userId;
        session.ApprovedByDeviceId = device.Id;
        session.Status = QrSessionStatus.Approved;
        session.ApprovedAt = DateTime.UtcNow;

        // Update device last used time
        device.LastUsedAt = DateTime.UtcNow;

        await _context.SaveChangesAsync();

        await LogDeviceActivityAsync(device.Id, userId, DeviceAuthActivity.QrLoginApproved, 
            clientId: session.ClientId, metadata: new { QrSessionId = session.Id });

        _logger.LogInformation("QR session {SessionId} approved by device {DeviceId} for user {UserId}", 
            session.Id, deviceId, userId);

        return true;
    }

    public async Task<bool> RejectQrSessionAsync(string token, string userId, string deviceId)
    {
        var session = await _context.PersistentQrSessions
            .FirstOrDefaultAsync(q => q.Token == token && q.Status == QrSessionStatus.Pending && q.ExpiresAt > DateTime.UtcNow);

        if (session == null)
            return false;

        var device = await _context.UserDevices
            .FirstOrDefaultAsync(d => d.UserId == userId && d.DeviceId == deviceId && d.IsActive);

        if (device == null)
            return false;

        session.Status = QrSessionStatus.Rejected;
        session.ApprovedAt = DateTime.UtcNow;

        await _context.SaveChangesAsync();

        await LogDeviceActivityAsync(device.Id, userId, DeviceAuthActivity.QrLoginRejected, 
            clientId: session.ClientId, metadata: new { QrSessionId = session.Id });

        _logger.LogInformation("QR session {SessionId} rejected by device {DeviceId} for user {UserId}", 
            session.Id, deviceId, userId);

        return true;
    }

    public async Task<bool> CompleteQrSessionAsync(string token)
    {
        var session = await _context.PersistentQrSessions
            .FirstOrDefaultAsync(q => q.Token == token && q.Status == QrSessionStatus.Approved);

        if (session == null)
            return false;

        session.Status = QrSessionStatus.Completed;
        session.CompletedAt = DateTime.UtcNow;

        await _context.SaveChangesAsync();

        _logger.LogInformation("QR session {SessionId} completed", session.Id);
        return true;
    }

    public async Task CleanupExpiredQrSessionsAsync()
    {
        var expiredSessions = await _context.PersistentQrSessions
            .Where(q => q.ExpiresAt <= DateTime.UtcNow && q.Status == QrSessionStatus.Pending)
            .ToListAsync();

        foreach (var session in expiredSessions)
        {
            session.Status = QrSessionStatus.Expired;
        }

        if (expiredSessions.Any())
        {
            await _context.SaveChangesAsync();
            _logger.LogInformation("Marked {Count} QR sessions as expired", expiredSessions.Count);
        }
    }

    // ============================================================================
    // DEVICE AUTHENTICATION LOGGING
    // ============================================================================

    public async Task LogDeviceActivityAsync(string deviceId, string userId, DeviceAuthActivity activity, 
        string? clientId = null, bool isSuccessful = true, string? errorMessage = null, 
        string? ipAddress = null, string? userAgent = null, object? metadata = null)
    {
        var log = new DeviceAuthenticationLog
        {
            DeviceId = deviceId,
            UserId = userId,
            ActivityType = activity,
            ClientId = clientId,
            IsSuccessful = isSuccessful,
            ErrorMessage = errorMessage,
            IpAddress = ipAddress,
            UserAgent = userAgent,
            Metadata = metadata != null ? JsonSerializer.Serialize(metadata) : null
        };

        _context.DeviceAuthenticationLogs.Add(log);
        
        try
        {
            await _context.SaveChangesAsync();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to log device activity for device {DeviceId}", deviceId);
        }
    }

    public async Task<List<DeviceAuthenticationLog>> GetDeviceActivityAsync(string deviceId, int count = 50)
    {
        return await _context.DeviceAuthenticationLogs
            .Where(l => l.DeviceId == deviceId)
            .OrderByDescending(l => l.OccurredAt)
            .Take(count)
            .ToListAsync();
    }

    public async Task<List<DeviceAuthenticationLog>> GetUserDeviceActivityAsync(string userId, int count = 100)
    {
        return await _context.DeviceAuthenticationLogs
            .Where(l => l.UserId == userId)
            .OrderByDescending(l => l.OccurredAt)
            .Take(count)
            .ToListAsync();
    }

    public async Task<bool> IsDeviceCompromisedAsync(string deviceId)
    {
        var compromisedLog = await _context.DeviceAuthenticationLogs
            .AnyAsync(l => l.DeviceId == deviceId && l.ActivityType == DeviceAuthActivity.DeviceCompromised);

        if (compromisedLog)
            return true;

        // Additional heuristics can be added here
        // e.g., multiple failed attempts, suspicious IP changes, etc.

        return false;
    }

    public async Task MarkDeviceCompromisedAsync(string deviceId, string reason)
    {
        var device = await _context.UserDevices
            .FirstOrDefaultAsync(d => d.DeviceId == deviceId);

        if (device == null)
            return;

        // Deactivate the device
        device.IsActive = false;
        device.IsTrusted = false;
        device.CanApproveLogins = false;
        device.UpdatedAt = DateTime.UtcNow;

        await _context.SaveChangesAsync();

        await LogDeviceActivityAsync(device.Id, device.UserId, DeviceAuthActivity.DeviceCompromised, 
            errorMessage: reason, metadata: new { Reason = reason, MarkedAt = DateTime.UtcNow });

        _logger.LogWarning("Marked device {DeviceId} as compromised: {Reason}", deviceId, reason);
    }

    // ============================================================================
    // HELPER METHODS
    // ============================================================================

    private static string GenerateSecureToken()
    {
        return Convert.ToBase64String(Guid.NewGuid().ToByteArray())
            .Replace("+", "-").Replace("/", "_").TrimEnd('=');
    }
}

// ============================================================================
// REQUEST/RESPONSE MODELS
// ============================================================================

public class RegisterDeviceRequest
{
    public required string DeviceId { get; set; }
    public required string DeviceName { get; set; }
    public DeviceType DeviceType { get; set; } = DeviceType.Unknown;
    public string? OperatingSystem { get; set; }
    public string? UserAgent { get; set; }
    public bool IsTrusted { get; set; } = false;
    public bool CanApproveLogins { get; set; } = true;
    public string? PushToken { get; set; }
    public string? PublicKey { get; set; }
    public string? IpAddress { get; set; }
    public DateTime? ExpiresAt { get; set; }
    public object? Metadata { get; set; }
}

public class UpdateDeviceRequest
{
    public string? DeviceName { get; set; }
    public DeviceType? DeviceType { get; set; }
    public string? OperatingSystem { get; set; }
    public string? UserAgent { get; set; }
    public bool? CanApproveLogins { get; set; }
    public string? PushToken { get; set; }
    public string? PublicKey { get; set; }
    public DateTime? ExpiresAt { get; set; }
    public object? Metadata { get; set; }
}

public class CreateQrSessionRequest
{
    public string? UserId { get; set; }
    public string? ClientId { get; set; }
    public string? ReturnUrl { get; set; }
    public TimeSpan? ExpirationDuration { get; set; }
    public string? IpAddress { get; set; }
    public object? Metadata { get; set; }
}