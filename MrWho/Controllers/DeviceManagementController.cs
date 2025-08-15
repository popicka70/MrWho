using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using MrWho.Models;
using MrWho.Services;
using MrWho.Shared;
using System.ComponentModel.DataAnnotations;
using System.Text.Json;

namespace MrWho.Controllers;

/// <summary>
/// API Controller for managing user devices and persistent QR code authentication
/// </summary>
[Route("api/devices")]
[ApiController]
[Authorize]
public class DeviceManagementController : ControllerBase
{
    private readonly IDeviceManagementService _deviceService;
    private readonly IEnhancedQrLoginService _qrService;
    private readonly UserManager<IdentityUser> _userManager;
    private readonly ILogger<DeviceManagementController> _logger;

    public DeviceManagementController(
        IDeviceManagementService deviceService,
        IEnhancedQrLoginService qrService,
        UserManager<IdentityUser> userManager,
        ILogger<DeviceManagementController> logger)
    {
        _deviceService = deviceService;
        _qrService = qrService;
        _userManager = userManager;
        _logger = logger;
    }

    // ============================================================================
    // DEVICE MANAGEMENT
    // ============================================================================

    /// <summary>
    /// Register a new device for the current user
    /// </summary>
    [HttpPost("register")]
    public async Task<ActionResult<UserDeviceDto>> RegisterDevice([FromBody] RegisterDeviceApiRequest request)
    {
        var user = await _userManager.GetUserAsync(User);
        if (user == null)
            return Unauthorized();

        try
        {
            var deviceRequest = new RegisterDeviceRequest
            {
                DeviceId = request.DeviceId,
                DeviceName = request.DeviceName,
                DeviceType = request.DeviceType,
                OperatingSystem = request.OperatingSystem,
                UserAgent = Request.Headers.UserAgent.ToString(),
                IsTrusted = request.IsTrusted,
                CanApproveLogins = request.CanApproveLogins,
                PushToken = request.PushToken,
                PublicKey = request.PublicKey,
                IpAddress = GetClientIpAddress(),
                ExpiresAt = request.ExpiresAt,
                Metadata = request.Metadata
            };

            var device = await _deviceService.RegisterDeviceAsync(user.Id, deviceRequest);
            
            _logger.LogInformation("Device {DeviceId} registered for user {UserId}", device.DeviceId, user.Id);
            
            return Ok(MapToDto(device));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error registering device for user {UserId}", user.Id);
            return StatusCode(500, new { error = "Failed to register device" });
        }
    }

    /// <summary>
    /// Get all devices for the current user
    /// </summary>
    [HttpGet]
    public async Task<ActionResult<List<UserDeviceDto>>> GetUserDevices([FromQuery] bool activeOnly = true)
    {
        var user = await _userManager.GetUserAsync(User);
        if (user == null)
            return Unauthorized();

        var devices = await _deviceService.GetUserDevicesAsync(user.Id, activeOnly);
        return Ok(devices.Select(MapToDto).ToList());
    }

    /// <summary>
    /// Get a specific device by device ID
    /// </summary>
    [HttpGet("{deviceId}")]
    public async Task<ActionResult<UserDeviceDto>> GetDevice(string deviceId)
    {
        var user = await _userManager.GetUserAsync(User);
        if (user == null)
            return Unauthorized();

        var device = await _deviceService.GetDeviceAsync(user.Id, deviceId);
        if (device == null)
            return NotFound();

        return Ok(MapToDto(device));
    }

    /// <summary>
    /// Update device information
    /// </summary>
    [HttpPut("{deviceId}")]
    public async Task<ActionResult> UpdateDevice(string deviceId, [FromBody] UpdateDeviceApiRequest request)
    {
        var user = await _userManager.GetUserAsync(User);
        if (user == null)
            return Unauthorized();

        // Verify device belongs to user
        var device = await _deviceService.GetDeviceAsync(user.Id, deviceId);
        if (device == null)
            return NotFound();

        var updateRequest = new UpdateDeviceRequest
        {
            DeviceName = request.DeviceName,
            DeviceType = request.DeviceType,
            OperatingSystem = request.OperatingSystem,
            UserAgent = request.UserAgent,
            CanApproveLogins = request.CanApproveLogins,
            PushToken = request.PushToken,
            PublicKey = request.PublicKey,
            ExpiresAt = request.ExpiresAt,
            Metadata = request.Metadata
        };

        var success = await _deviceService.UpdateDeviceAsync(deviceId, updateRequest);
        if (!success)
            return NotFound();

        _logger.LogInformation("Device {DeviceId} updated for user {UserId}", deviceId, user.Id);
        return NoContent();
    }

    /// <summary>
    /// Revoke/deactivate a device
    /// </summary>
    [HttpDelete("{deviceId}")]
    public async Task<ActionResult> RevokeDevice(string deviceId)
    {
        var user = await _userManager.GetUserAsync(User);
        if (user == null)
            return Unauthorized();

        var success = await _deviceService.RevokeDeviceAsync(user.Id, deviceId);
        if (!success)
            return NotFound();

        _logger.LogInformation("Device {DeviceId} revoked for user {UserId}", deviceId, user.Id);
        return NoContent();
    }

    /// <summary>
    /// Set device trusted status
    /// </summary>
    [HttpPost("{deviceId}/trust")]
    public async Task<ActionResult> SetDeviceTrusted(string deviceId, [FromBody] SetTrustedRequest request)
    {
        var user = await _userManager.GetUserAsync(User);
        if (user == null)
            return Unauthorized();

        var success = await _deviceService.SetDeviceTrustedAsync(user.Id, deviceId, request.IsTrusted);
        if (!success)
            return NotFound();

        _logger.LogInformation("Device {DeviceId} trusted status set to {Trusted} for user {UserId}", 
            deviceId, request.IsTrusted, user.Id);
        return NoContent();
    }

    // ============================================================================
    // QR CODE AUTHENTICATION
    // ============================================================================

    /// <summary>
    /// Create a persistent QR code session for authentication
    /// </summary>
    [HttpPost("qr/create")]
    [AllowAnonymous]
    public async Task<ActionResult<CreateQrResponse>> CreateQrSession([FromBody] CreateQrApiRequest request)
    {
        try
        {
            var token = await _qrService.CreatePersistentQrAsync(
                userId: null, // Will be set when approved
                clientId: request.ClientId,
                returnUrl: request.ReturnUrl,
                ttl: TimeSpan.FromMinutes(request.ExpirationMinutes ?? 5)
            );

            return Ok(new CreateQrResponse
            {
                Token = token,
                QrCodeUrl = Url.Action("QrPng", "QrLogin", new { token }, Request.Scheme),
                // Point approval to the Web UI controller so users can select a device
                ApprovalUrl = Url.Action("ApprovePersistent", "DeviceManagementWeb", new { token }, Request.Scheme),
                ExpiresAt = DateTime.UtcNow.AddMinutes(request.ExpirationMinutes ?? 5)
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error creating QR session");
            return StatusCode(500, new { error = "Failed to create QR session" });
        }
    }

    /// <summary>
    /// Get QR session status
    /// </summary>
    [HttpGet("qr/{token}/status")]
    [AllowAnonymous]
    public async Task<ActionResult<QrSessionStatusResponse>> GetQrStatus(string token)
    {
        try
        {
            var sessionInfo = await _qrService.GetQrSessionInfoAsync(token);
            
            return Ok(new QrSessionStatusResponse
            {
                Status = sessionInfo.Status.ToString(),
                IsApproved = sessionInfo.Status == QrSessionStatusEnum.Approved || 
                           sessionInfo.Status == QrSessionStatusEnum.Completed,
                ApprovedAt = sessionInfo.ApprovedAt,
                DeviceName = sessionInfo.DeviceName,
                ExpiresAt = sessionInfo.ExpiresAt
            });
        }
        catch (ArgumentException)
        {
            return NotFound(new { status = "expired" });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting QR status for token {Token}", token);
            return StatusCode(500, new { error = "Failed to get QR status" });
        }
    }

    /// <summary>
    /// Approve a QR code session using a registered device
    /// </summary>
    [HttpPost("qr/{token}/approve")]
    public async Task<ActionResult> ApproveQrSession(string token, [FromBody] ApproveQrRequest request)
    {
        var user = await _userManager.GetUserAsync(User);
        if (user == null)
            return Unauthorized();

        try
        {
            var success = await _qrService.ApproveQrAsync(token, user.Id, request.DeviceId);
            if (!success)
                return BadRequest(new { error = "Failed to approve QR session. Session may be expired or device invalid." });

            _logger.LogInformation("QR session {Token} approved by user {UserId} with device {DeviceId}", 
                token, user.Id, request.DeviceId);

            return Ok(new { message = "QR session approved successfully" });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error approving QR session {Token} for user {UserId}", token, user.Id);
            return StatusCode(500, new { error = "Failed to approve QR session" });
        }
    }

    /// <summary>
    /// Reject a QR code session
    /// </summary>
    [HttpPost("qr/{token}/reject")]
    public async Task<ActionResult> RejectQrSession(string token, [FromBody] RejectQrRequest request)
    {
        var user = await _userManager.GetUserAsync(User);
        if (user == null)
            return Unauthorized();

        try
        {
            var success = await _qrService.RejectPersistentQrAsync(token, user.Id, request.DeviceId);
            if (!success)
                return BadRequest(new { error = "Failed to reject QR session. Session may be expired or device invalid." });

            _logger.LogInformation("QR session {Token} rejected by user {UserId} with device {DeviceId}", 
                token, user.Id, request.DeviceId);

            return Ok(new { message = "QR session rejected successfully" });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error rejecting QR session {Token} for user {UserId}", token, user.Id);
            return StatusCode(500, new { error = "Failed to reject QR session" });
        }
    }

    // ============================================================================
    // DEVICE ACTIVITY & SECURITY
    // ============================================================================

    /// <summary>
    /// Get authentication activity for a specific device
    /// </summary>
    [HttpGet("{deviceId}/activity")]
    public async Task<ActionResult<List<DeviceActivityDto>>> GetDeviceActivity(string deviceId, [FromQuery] int count = 50)
    {
        var user = await _userManager.GetUserAsync(User);
        if (user == null)
            return Unauthorized();

        // Verify device belongs to user
        var device = await _deviceService.GetDeviceAsync(user.Id, deviceId);
        if (device == null)
            return NotFound();

        var activity = await _deviceService.GetDeviceActivityAsync(device.Id, count);
        return Ok(activity.Select(MapActivityToDto).ToList());
    }

    /// <summary>
    /// Get all device activity for the current user
    /// </summary>
    [HttpGet("activity")]
    public async Task<ActionResult<List<DeviceActivityDto>>> GetUserDeviceActivity([FromQuery] int count = 100)
    {
        var user = await _userManager.GetUserAsync(User);
        if (user == null)
            return Unauthorized();

        var activity = await _deviceService.GetUserDeviceActivityAsync(user.Id, count);
        return Ok(activity.Select(MapActivityToDto).ToList());
    }

    /// <summary>
    /// Mark a device as compromised
    /// </summary>
    [HttpPost("{deviceId}/compromised")]
    public async Task<ActionResult> MarkDeviceCompromised(string deviceId, [FromBody] MarkCompromisedRequest request)
    {
        var user = await _userManager.GetUserAsync(User);
        if (user == null)
            return Unauthorized();

        // Verify device belongs to user
        var device = await _deviceService.GetDeviceAsync(user.Id, deviceId);
        if (device == null)
            return NotFound();

        await _deviceService.MarkDeviceCompromisedAsync(deviceId, request.Reason);

        _logger.LogWarning("Device {DeviceId} marked as compromised by user {UserId}: {Reason}", 
            deviceId, user.Id, request.Reason);

        return Ok(new { message = "Device marked as compromised and deactivated" });
    }

    // ============================================================================
    // HELPER METHODS
    // ============================================================================

    private string GetClientIpAddress()
    {
        return HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
    }

    private static UserDeviceDto MapToDto(UserDevice device)
    {
        return new UserDeviceDto
        {
            Id = device.Id,
            DeviceId = device.DeviceId,
            DeviceName = device.DeviceName,
            DeviceType = device.DeviceType,
            OperatingSystem = device.OperatingSystem,
            UserAgent = device.UserAgent,
            IsTrusted = device.IsTrusted,
            CanApproveLogins = device.CanApproveLogins,
            IsActive = device.IsActive,
            LastUsedAt = device.LastUsedAt,
            LastIpAddress = device.LastIpAddress,
            LastLocation = device.LastLocation,
            CreatedAt = device.CreatedAt,
            UpdatedAt = device.UpdatedAt,
            ExpiresAt = device.ExpiresAt
        };
    }

    private static DeviceActivityDto MapActivityToDto(DeviceAuthenticationLog log)
    {
        return new DeviceActivityDto
        {
            Id = log.Id,
            ActivityType = log.ActivityType,
            ClientId = log.ClientId,
            IsSuccessful = log.IsSuccessful,
            ErrorMessage = log.ErrorMessage,
            IpAddress = log.IpAddress,
            UserAgent = log.UserAgent,
            OccurredAt = log.OccurredAt,
            Metadata = !string.IsNullOrEmpty(log.Metadata) ? JsonSerializer.Deserialize<JsonElement>(log.Metadata) : null
        };
    }
}

// ============================================================================
// API REQUEST/RESPONSE MODELS
// ============================================================================

public class RegisterDeviceApiRequest
{
    [Required]
    public string DeviceId { get; set; } = string.Empty;
    
    [Required]
    public string DeviceName { get; set; } = string.Empty;
    
    public DeviceType DeviceType { get; set; } = DeviceType.Unknown;
    
    public string? OperatingSystem { get; set; }
    
    public bool IsTrusted { get; set; } = false;
    
    public bool CanApproveLogins { get; set; } = true;
    
    public string? PushToken { get; set; }
    
    public string? PublicKey { get; set; }
    
    public DateTime? ExpiresAt { get; set; }
    
    public object? Metadata { get; set; }
}

public class UpdateDeviceApiRequest
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

public class SetTrustedRequest
{
    public bool IsTrusted { get; set; }
}

public class CreateQrApiRequest
{
    public string? ClientId { get; set; }
    public string? ReturnUrl { get; set; }
    public int? ExpirationMinutes { get; set; } = 5;
}

public class ApproveQrRequest
{
    [Required]
    public string DeviceId { get; set; } = string.Empty;
}

public class RejectQrRequest
{
    [Required]
    public string DeviceId { get; set; } = string.Empty;
}

public class MarkCompromisedRequest
{
    [Required]
    public string Reason { get; set; } = string.Empty;
}

public class CreateQrResponse
{
    public string Token { get; set; } = string.Empty;
    public string? QrCodeUrl { get; set; }
    public string? ApprovalUrl { get; set; }
    public DateTime ExpiresAt { get; set; }
}

public class QrSessionStatusResponse
{
    public string Status { get; set; } = string.Empty;
    public bool IsApproved { get; set; }
    public DateTime? ApprovedAt { get; set; }
    public string? DeviceName { get; set; }
    public DateTime ExpiresAt { get; set; }
}

public class UserDeviceDto
{
    public string Id { get; set; } = string.Empty;
    public string DeviceId { get; set; } = string.Empty;
    public string DeviceName { get; set; } = string.Empty;
    public DeviceType DeviceType { get; set; }
    public string? OperatingSystem { get; set; }
    public string? UserAgent { get; set; }
    public bool IsTrusted { get; set; }
    public bool CanApproveLogins { get; set; }
    public bool IsActive { get; set; }
    public DateTime? LastUsedAt { get; set; }
    public string? LastIpAddress { get; set; }
    public string? LastLocation { get; set; }
    public DateTime CreatedAt { get; set; }
    public DateTime UpdatedAt { get; set; }
    public DateTime? ExpiresAt { get; set; }
}

public class DeviceActivityDto
{
    public string Id { get; set; } = string.Empty;
    public DeviceAuthActivity ActivityType { get; set; }
    public string? ClientId { get; set; }
    public bool IsSuccessful { get; set; }
    public string? ErrorMessage { get; set; }
    public string? IpAddress { get; set; }
    public string? UserAgent { get; set; }
    public DateTime OccurredAt { get; set; }
    public JsonElement? Metadata { get; set; }
}