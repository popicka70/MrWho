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
    private readonly UserManager<IdentityUser> _userManager;
    private readonly ILogger<DeviceManagementWebController> _logger;

    public DeviceManagementWebController(
        IDeviceManagementService deviceService,
        UserManager<IdentityUser> userManager,
        ILogger<DeviceManagementWebController> logger)
    {
        _deviceService = deviceService;
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
    public IActionResult ApprovePersistent(string token) => NotFound();

    /// <summary>
    /// Process persistent QR approval
    /// </summary>
    [HttpPost("approve-persistent/{token}")]
    [ValidateAntiForgeryToken]
    public IActionResult ApprovePersistentPost(string token, [FromForm] string deviceId, [FromForm] string action) => NotFound();

    /// <summary>
    /// Device registration page
    /// </summary>
    [HttpGet("register")]
    public IActionResult Register() => View();

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
        
        TempData[success ? "SuccessMessage" : "ErrorMessage"] = success ? "Device revoked." : "Failed to revoke.";
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