using MrWho.Data;
using Microsoft.EntityFrameworkCore;
using MrWho.Models;
using MrWho.Shared;

namespace MrWho.Services;

// New persistent QR session DTO
public sealed class QrLoginDto
{
    public required string Token { get; init; }
    public required string Csrf { get; init; }
    public string? ClientId { get; init; }
    public string? ReturnUrl { get; init; }
    public DateTime ExpiresAt { get; init; }
    public MrWho.Shared.QrSessionStatus Status { get; init; }
    public string? DeviceId { get; init; }
    public string? UserId { get; init; }
    public DateTime? ApprovedAt { get; init; }
    public DateTime? CompletedAt { get; init; }
}

public interface IPersistentQrLoginService
{
    Task<QrLoginDto> CreateAsync(string? clientId, string? returnUrl, string? deviceId, TimeSpan? ttl = null, string? initiatorIp = null, CancellationToken ct = default);
    Task<QrLoginDto?> GetAsync(string token, CancellationToken ct = default);
    Task<bool> ApproveAsync(string token, string approverUserId, string deviceId, string csrf, CancellationToken ct = default);
    Task<bool> CompleteAsync(string token, string csrf, CancellationToken ct = default);
    Task<bool> RejectAsync(string token, string approverUserId, string deviceId, string csrf, CancellationToken ct = default);
}

public sealed class PersistentQrLoginService : IPersistentQrLoginService
{
    private readonly ApplicationDbContext _db;
    private readonly ILogger<PersistentQrLoginService> _logger;

    public PersistentQrLoginService(ApplicationDbContext db, ILogger<PersistentQrLoginService> logger)
    {
        _db = db; _logger = logger;
    }

    public async Task<QrLoginDto> CreateAsync(string? clientId, string? returnUrl, string? deviceId, TimeSpan? ttl = null, string? initiatorIp = null, CancellationToken ct = default)
    {
        var token = GenerateToken();
        var csrf = GenerateToken();
        var entity = new PersistentQrSession
        {
            Token = token,
            ClientId = clientId,
            ReturnUrl = returnUrl,
            ExpiresAt = DateTime.UtcNow.Add(ttl ?? TimeSpan.FromMinutes(5)),
            InitiatorIpAddress = initiatorIp,
            Metadata = csrf // store CSRF secret in Metadata field (simple reuse)
        };
        _db.PersistentQrSessions.Add(entity);
        await _db.SaveChangesAsync(ct);
        _logger.LogInformation("[QR] Created persistent QR token {Token} client {ClientId} exp {Exp}", token, clientId, entity.ExpiresAt);
        return ToDto(entity, csrf);
    }

    public async Task<QrLoginDto?> GetAsync(string token, CancellationToken ct = default)
    {
        var entity = await _db.PersistentQrSessions.Include(s=>s.ApprovedByDevice).FirstOrDefaultAsync(s=>s.Token==token, ct);
        if (entity == null) return null;
        if (entity.ExpiresAt <= DateTime.UtcNow && entity.Status == MrWho.Shared.QrSessionStatus.Pending)
        {
            entity.Status = MrWho.Shared.QrSessionStatus.Expired;
            await _db.SaveChangesAsync(ct);
        }
        return ToDto(entity, entity.Metadata); // Metadata holds csrf
    }

    public async Task<bool> ApproveAsync(string token, string approverUserId, string deviceId, string csrf, CancellationToken ct = default)
    {
        var entity = await _db.PersistentQrSessions.FirstOrDefaultAsync(s=>s.Token==token, ct);
        if (entity == null) return false;
        if (!Validate(entity, csrf, MrWho.Shared.QrSessionStatus.Pending)) return false;
        var device = await _db.UserDevices.FirstOrDefaultAsync(d=>d.UserId==approverUserId && d.DeviceId==deviceId && d.CanApproveLogins && d.IsActive, ct);
        if (device == null) return false;
        entity.UserId = approverUserId;
        entity.ApprovedByDeviceId = device.Id;
        entity.Status = MrWho.Shared.QrSessionStatus.Approved;
        entity.ApprovedAt = DateTime.UtcNow;
        await _db.SaveChangesAsync(ct);
        _logger.LogInformation("[QR] Approved token {Token} by device {DeviceId} user {UserId}", token, deviceId, approverUserId);
        return true;
    }

    public async Task<bool> CompleteAsync(string token, string csrf, CancellationToken ct = default)
    {
        var entity = await _db.PersistentQrSessions.FirstOrDefaultAsync(s=>s.Token==token, ct);
        if (entity == null) return false;
        if (!Validate(entity, csrf, MrWho.Shared.QrSessionStatus.Approved)) return false;
        entity.Status = MrWho.Shared.QrSessionStatus.Completed;
        entity.CompletedAt = DateTime.UtcNow;
        await _db.SaveChangesAsync(ct);
        _logger.LogInformation("[QR] Completed token {Token}", token);
        return true;
    }

    public async Task<bool> RejectAsync(string token, string approverUserId, string deviceId, string csrf, CancellationToken ct = default)
    {
        var entity = await _db.PersistentQrSessions.FirstOrDefaultAsync(s=>s.Token==token, ct);
        if (entity == null) return false;
        if (!Validate(entity, csrf, MrWho.Shared.QrSessionStatus.Pending)) return false;
        var device = await _db.UserDevices.FirstOrDefaultAsync(d=>d.UserId==approverUserId && d.DeviceId==deviceId && d.IsActive, ct);
        if (device == null) return false;
        entity.Status = MrWho.Shared.QrSessionStatus.Rejected;
        entity.ApprovedAt = DateTime.UtcNow;
        await _db.SaveChangesAsync(ct);
        _logger.LogInformation("[QR] Rejected token {Token} by device {DeviceId} user {UserId}", token, deviceId, approverUserId);
        return true;
    }

    private static string GenerateToken() => Convert.ToBase64String(Guid.NewGuid().ToByteArray()).Replace('+','-').Replace('/','_').TrimEnd('=');

    private static bool Validate(PersistentQrSession entity, string csrf, MrWho.Shared.QrSessionStatus required)
    {
        if (entity.Metadata != csrf) return false; // CSRF mismatch
        if (entity.Status != required) return false;
        if (entity.ExpiresAt <= DateTime.UtcNow && entity.Status == MrWho.Shared.QrSessionStatus.Pending) return false;
        return true;
    }

    private static QrLoginDto ToDto(PersistentQrSession e, string? csrf) => new()
    {
        Token = e.Token,
        Csrf = csrf ?? string.Empty,
        ClientId = e.ClientId,
        ReturnUrl = e.ReturnUrl,
        ExpiresAt = e.ExpiresAt,
        Status = e.Status,
        DeviceId = e.ApprovedByDeviceId,
        UserId = e.UserId,
        ApprovedAt = e.ApprovedAt,
        CompletedAt = e.CompletedAt
    };
}
