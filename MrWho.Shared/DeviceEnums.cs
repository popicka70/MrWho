namespace MrWho.Shared;

/// <summary>
/// Types of devices that can be registered
/// </summary>
public enum DeviceType
{
    Unknown = 0,
    Phone = 1,
    Tablet = 2,
    Desktop = 3,
    Laptop = 4,
    SmartWatch = 5,
    SmartTv = 6,
    GameConsole = 7,
    IoTDevice = 8,
    WebBrowser = 9
}

/// <summary>
/// Status of a QR code authentication session
/// </summary>
public enum QrSessionStatus
{
    Pending = 0,        // QR code displayed, waiting for approval
    Approved = 1,       // User approved on their device
    Completed = 2,      // Session completed successfully
    Expired = 3,        // Session timed out
    Rejected = 4,       // User explicitly rejected
    Failed = 5          // Technical failure occurred
}

/// <summary>
/// Types of device authentication activities for logging
/// </summary>
public enum DeviceAuthActivity
{
    DeviceRegistered = 0,       // Device was registered/paired
    QrLoginApproved = 1,        // Device approved a QR login
    QrLoginRejected = 2,        // Device rejected a QR login
    PasswordlessLogin = 3,      // Device performed passwordless login
    DeviceRevoked = 4,          // Device was revoked/removed
    DeviceUpdated = 5,          // Device information was updated
    SecurityAlert = 6,          // Security-related event
    PushNotificationSent = 7,   // Push notification was sent
    PushNotificationFailed = 8, // Push notification failed
    DeviceCompromised = 9       // Device marked as compromised
}