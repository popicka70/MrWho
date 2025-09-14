using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using MrWho.Services;
using QRCoder;

namespace MrWho.Controllers;

/// <summary>
/// Web UI Controller for device management and persistent QR approval
/// </summary>
[Route("device-management")]
[Authorize]
public class DeviceManagementWebController : Controller
{
    private readonly IDeviceManagementService _deviceService;
    private readonly IEnhancedQrLoginService _qrService;
    private readonly UserManager<IdentityUser> _userManager;
    private readonly ILogger<DeviceManagementWebController> _logger;

    public DeviceManagementWebController(
        IDeviceManagementService deviceService,
        IEnhancedQrLoginService qrService,
        UserManager<IdentityUser> userManager,
        ILogger<DeviceManagementWebController> logger)
    {
        _deviceService = deviceService;
        _qrService = qrService;
        _userManager = userManager;
        _logger = logger;
    }

    /// <summary>
    /// Device management dashboard
    /// </summary>
    [HttpGet]
    public async Task<IActionResult> Index()
    {
        var user = await _userManager.GetUserAsync(User);
        if (user == null)
            return Challenge();

        var devices = await _deviceService.GetUserDevicesAsync(user.Id);
        return View(devices);
    }

    /// <summary>
    /// Approve a persistent QR code session
    /// </summary>
    [HttpGet("approve-persistent/{token}")]
    public async Task<IActionResult> ApprovePersistent(string token)
    {
        try
        {
            var sessionInfo = await _qrService.GetQrSessionInfoAsync(token);
            if (sessionInfo.Type != QrSessionType.Persistent)
            {
                return View("ApprovalError", model: "This QR code is not a persistent session.");
            }

            if (sessionInfo.Status != QrSessionStatusEnum.Pending)
            {
                return View("ApprovalError", model: "This QR session has expired or is no longer valid.");
            }

            var user = await _userManager.GetUserAsync(User);
            if (user == null)
                return Challenge();

            // Get user's devices that can approve logins
            var devices = await _deviceService.GetUserDevicesAsync(user.Id);
            var availableDevices = devices.Where(d => d.CanApproveLogins).ToList();

            ViewData["Token"] = token;
            ViewData["SessionInfo"] = sessionInfo;
            ViewData["AvailableDevices"] = availableDevices;

            return View("ApprovePersistent");
        }
        catch (ArgumentException)
        {
            return View("ApprovalError", model: "QR session not found or expired.");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error loading persistent QR approval page for token {Token}", token);
            return View("ApprovalError", model: "An error occurred while loading the approval page.");
        }
    }

    /// <summary>
    /// Process persistent QR approval
    /// </summary>
    [HttpPost("approve-persistent/{token}")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> ApprovePersistentPost(string token, [FromForm] string deviceId, [FromForm] string action)
    {
        var user = await _userManager.GetUserAsync(User);
        if (user == null)
            return Challenge();

        try
        {
            bool success;
            string actionMessage;

            if (action == "approve")
            {
                success = await _qrService.ApprovePersistentQrAsync(token, user.Id, deviceId);
                actionMessage = success ? "QR login approved successfully!" : "Failed to approve QR login.";
            }
            else if (action == "reject")
            {
                success = await _qrService.RejectPersistentQrAsync(token, user.Id, deviceId);
                actionMessage = success ? "QR login rejected." : "Failed to reject QR login.";
            }
            else
            {
                return BadRequest("Invalid action.");
            }

            if (success)
            {
                _logger.LogInformation("QR session {Token} {Action} by user {UserId} with device {DeviceId}",
                    token, action, user.Id, deviceId);
                return View("ApprovalSuccess", model: actionMessage);
            }
            else
            {
                return View("ApprovalError", model: actionMessage);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error processing persistent QR {Action} for token {Token}", action, token);
            return View("ApprovalError", model: "An error occurred while processing your request.");
        }
    }

    /// <summary>
    /// Device registration page
    /// </summary>
    [HttpGet("register")]
    public IActionResult Register()
    {
        return View();
    }

    /// <summary>
    /// Process device registration
    /// </summary>
    [HttpPost("register")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Register([FromForm] string deviceName, [FromForm] string deviceId, [FromForm] bool isTrusted = false)
    {
        var user = await _userManager.GetUserAsync(User);
        if (user == null)
            return Challenge();

        try
        {
            var request = new RegisterDeviceRequest
            {
                DeviceId = deviceId ?? Guid.NewGuid().ToString(),
                DeviceName = deviceName,
                DeviceType = Shared.DeviceType.WebBrowser, // Default for web registration
                UserAgent = Request.Headers.UserAgent.ToString(),
                IsTrusted = isTrusted,
                CanApproveLogins = true,
                IpAddress = HttpContext.Connection.RemoteIpAddress?.ToString()
            };

            var device = await _deviceService.RegisterDeviceAsync(user.Id, request);

            _logger.LogInformation("Device {DeviceId} registered via web for user {UserId}", device.DeviceId, user.Id);

            TempData["SuccessMessage"] = $"Device '{device.DeviceName}' registered successfully!";
            return RedirectToAction("Index");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error registering device via web for user {UserId}", user.Id);
            TempData["ErrorMessage"] = "Failed to register device. Please try again.";
            return View();
        }
    }

    /// <summary>
    /// Device activity page
    /// </summary>
    [HttpGet("activity")]
    public async Task<IActionResult> Activity()
    {
        var user = await _userManager.GetUserAsync(User);
        if (user == null)
            return Challenge();

        var activity = await _deviceService.GetUserDeviceActivityAsync(user.Id, 50);
        return View(activity);
    }

    /// <summary>
    /// Revoke a device
    /// </summary>
    [HttpPost("revoke/{deviceId}")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> RevokeDevice(string deviceId)
    {
        var user = await _userManager.GetUserAsync(User);
        if (user == null)
            return Challenge();

        var success = await _deviceService.RevokeDeviceAsync(user.Id, deviceId);

        if (success)
        {
            TempData["SuccessMessage"] = "Device revoked successfully.";
            _logger.LogInformation("Device {DeviceId} revoked via web for user {UserId}", deviceId, user.Id);
        }
        else
        {
            TempData["ErrorMessage"] = "Failed to revoke device.";
        }

        return RedirectToAction("Index");
    }

    /// <summary>
    /// Generate QR code for device registration
    /// </summary>
    [HttpGet("register-qr.png")]
    public IActionResult RegisterQrPng()
    {
        // Generate the URL for device registration
        var registrationUrl = Url.Action("Register", "DeviceManagementWeb", null, Request.Scheme, Request.Host.ToString())!;

        using var generator = new QRCodeGenerator();
        var data = generator.CreateQrCode(registrationUrl, QRCodeGenerator.ECCLevel.Q);
        var png = new PngByteQRCode(data).GetGraphic(8);
        return File(png, "image/png");
    }

    /// <summary>
    /// Show QR code for mobile device registration
    /// </summary>
    [HttpGet("register-qr")]
    public IActionResult RegisterQr()
    {
        var registrationUrl = Url.Action("Register", "DeviceManagementWeb", null, Request.Scheme, Request.Host.ToString())!;
        ViewData["RegistrationUrl"] = registrationUrl;
        return View();
    }
}