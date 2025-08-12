# Device Management & Enhanced QR Login System

## ?? Overview

The MrWho OIDC Server now includes a comprehensive **Device Management System** with **Enhanced QR Login** capabilities. This system provides persistent device registration, advanced authentication workflows, and enterprise-grade security monitoring while maintaining backward compatibility with the original session-based QR login.

## ?? Key Features

### ?? Device Registration & Management
- **Multi-Device Support**: Register phones, tablets, laptops, smart watches, and more
- **Device Metadata**: Track OS, browser, IP addresses, locations, and usage patterns
- **Trusted Devices**: Mark devices as trusted for enhanced security privileges
- **Device Lifecycle**: Full device lifecycle management from registration to revocation
- **Security Monitoring**: Real-time monitoring of device activities and security events

### ?? Enhanced QR Code Authentication
- **Dual QR Modes**: Choose between session-based (quick) or persistent (secure)
- **Device-Specific Approval**: Use registered devices to approve login attempts
- **Rejection Support**: Explicitly reject suspicious or unwanted login attempts
- **Complete Audit Trail**: Every approval/rejection is logged with device and location info
- **Backward Compatible**: Original QR login continues to work seamlessly

### ??? Security & Compliance
- **Authentication Logging**: Comprehensive audit trails for compliance requirements
- **Compromise Detection**: Automatic detection and handling of compromised devices
- **IP Tracking**: Monitor device locations and detect suspicious movements
- **Activity Analytics**: Detailed insights into authentication patterns and usage
- **Instant Revocation**: Immediately disable compromised or lost devices

## ?? Architecture

### Database Schema
```
UserDevice
??? Device identification (DeviceId, DeviceName, DeviceType)
??? Security attributes (IsTrusted, CanApproveLogins, IsActive)
??? Metadata (OS, UserAgent, LastUsedAt, LastIpAddress)
??? Audit (CreatedAt, UpdatedAt, ExpiresAt)

PersistentQrSession
??? Session management (Token, Status, ExpiresAt)
??? Approval tracking (ApprovedByDeviceId, ApprovedAt)
??? Context (UserId, ClientId, ReturnUrl)
??? Security (InitiatorIpAddress, ApproverIpAddress)

DeviceAuthenticationLog
??? Activity tracking (ActivityType, IsSuccessful, OccurredAt)
??? Context (DeviceId, UserId, ClientId)
??? Security (IpAddress, UserAgent, ErrorMessage)
??? Metadata (JSON for additional context)
```

### Service Architecture
```
IEnhancedQrLoginService (Unified QR Interface)
??? Session-based QR (Original, fast, temporary)
??? Persistent QR (New, secure, device-tracked)

IDeviceManagementService (Core Device Logic)
??? Device registration and lifecycle
??? QR session management
??? Security monitoring and logging
??? Compromise detection and handling

Controllers & APIs
??? DeviceManagementController (REST API)
??? DeviceManagementWebController (Web UI)
??? QrLoginController (Enhanced with dual modes)
```

## ?? Usage Scenarios

### Scenario 1: Employee Onboarding
1. **Register Work Devices**: Employee registers work laptop and personal phone
2. **Set Trust Levels**: Work laptop marked as trusted, phone for approvals only
3. **Secure Access**: Laptop gets passwordless access, phone used for QR approvals
4. **Monitoring**: IT can track all authentication activities and device usage

### Scenario 2: Consumer Application
1. **Easy Registration**: User registers their phone with one-click setup
2. **Seamless Login**: QR codes provide quick access from any device
3. **Family Sharing**: Multiple family members can register devices to shared account
4. **Security**: Instant device revocation if phone is lost or stolen

### Scenario 3: Enterprise Security
1. **Policy Enforcement**: Only trusted devices can access sensitive resources
2. **Audit Compliance**: Complete logs for SOX, GDPR, HIPAA compliance
3. **Threat Detection**: Automatic alerts for suspicious authentication patterns
4. **Incident Response**: Quick device revocation and forensic trail analysis

## ?? API Reference

### Device Management REST API

#### Register Device
```http
POST /api/devices/register
Content-Type: application/json

{
  "deviceId": "unique-device-identifier",
  "deviceName": "John's iPhone",
  "deviceType": "Phone",
  "operatingSystem": "iOS 17.1",
  "isTrusted": false,
  "canApproveLogins": true,
  "pushToken": "fcm-token-here",
  "publicKey": "device-public-key"
}
```

#### List User Devices
```http
GET /api/devices?activeOnly=true
```

#### Get Device Activity
```http
GET /api/devices/{deviceId}/activity?count=50
```

#### Revoke Device
```http
DELETE /api/devices/{deviceId}
```

### Enhanced QR Authentication API

#### Create Persistent QR Session
```http
POST /api/devices/qr/create
Content-Type: application/json

{
  "clientId": "my-app",
  "returnUrl": "https://myapp.com/auth/callback",
  "expirationMinutes": 5
}
```

#### Check QR Status
```http
GET /api/devices/qr/{token}/status
```

#### Approve QR Session
```http
POST /api/devices/qr/{token}/approve
Content-Type: application/json

{
  "deviceId": "approving-device-id"
}
```

### Traditional QR Login (Backward Compatible)
```http
# Original session-based QR still works
GET /qr-login/start?clientId=my-app&returnUrl=callback-url
GET /qr-login/status?token=session-token
GET /qr-login/approve?token=session-token
```

## ??? Web Interface

### Device Management Dashboard (`/device-management`)
- **Device Grid**: Visual overview of all registered devices
- **Device Details**: OS, last used, IP address, trust status
- **Quick Actions**: Revoke devices, view activity, mark as trusted
- **Registration**: Simple form to register new devices
- **Activity Feed**: Real-time stream of authentication events

### QR Login Pages
- **Enhanced Start** (`/qr-login/start?persistent=true`): Device-backed QR sessions
- **Approval Interface**: Select which registered device to use for approval
- **Success/Error Pages**: Clear feedback on approval outcomes
- **Activity Logs**: Complete audit trail of QR authentication events

## ?? Security Features

### Device Trust Levels
```csharp
public enum DeviceType
{
    Unknown, Phone, Tablet, Desktop, Laptop, 
    SmartWatch, SmartTv, GameConsole, IoTDevice, WebBrowser
}

// Trust and capability management
device.IsTrusted = true;           // Can perform passwordless auth
device.CanApproveLogins = true;    // Can approve QR logins
device.IsActive = true;            // Currently enabled
```

### Activity Monitoring
```csharp
public enum DeviceAuthActivity
{
    DeviceRegistered, QrLoginApproved, QrLoginRejected,
    PasswordlessLogin, DeviceRevoked, DeviceUpdated,
    SecurityAlert, DeviceCompromised
}
```

### Audit Trail
Every authentication event is logged with:
- **What**: Type of activity (login, approval, registration, etc.)
- **Who**: User and device involved
- **When**: Precise timestamp
- **Where**: IP address and location (if available)
- **How**: Success/failure and error details
- **Context**: Client application, session metadata

## ?? Getting Started

### 1. Database Setup
The device management system requires new database tables. Run migrations:
```bash
dotnet ef database update
```

### 2. Service Registration
Services are automatically registered via `AddMrWhoServices()`:
```csharp
// Already included in Program.cs
builder.Services.AddMrWhoServices(); // Includes device management
```

### 3. Register Your First Device
```bash
# Via Web UI
curl -X POST https://localhost:7113/device-management/register \
  -d "deviceName=My Phone&deviceId=my-phone-123"

# Via API
curl -X POST https://localhost:7113/api/devices/register \
  -H "Content-Type: application/json" \
  -d '{"deviceId":"my-phone-123","deviceName":"My Phone","deviceType":"Phone"}'
```

### 4. Test Enhanced QR Login
1. Visit: `https://localhost:7113/qr-login/start?persistent=true`
2. Scan QR code on registered device
3. Choose device for approval
4. Complete authentication on original device

## ?? Configuration

### Device Session Timeouts
Configure per-client device session durations:
```csharp
services.AddClientSpecificCookie("my-client", options =>
{
    options.ExpireTimeSpan = TimeSpan.FromHours(8); // Work day session
});
```

### Security Policies
```csharp
services.AddAuthorization(options =>
{
    options.AddPolicy("RequireDeviceRegistration", policy =>
        policy.RequireClaim("device_registered", "true"));
    
    options.AddPolicy("RequireTrustedDevice", policy =>
        policy.RequireClaim("device_trusted", "true"));
});
```

### Activity Logging
```csharp
// Log custom device activities
await _deviceService.LogDeviceActivityAsync(
    deviceId: "device-123",
    userId: "user-456", 
    activity: DeviceAuthActivity.SecurityAlert,
    errorMessage: "Suspicious IP change detected",
    metadata: new { OldIP = "1.2.3.4", NewIP = "5.6.7.8" }
);
```

## ?? Monitoring & Analytics

### Built-in Reports
- **Device Registration Trends**: Track device adoption over time
- **Authentication Patterns**: Analyze login frequency and patterns
- **Security Events**: Monitor failed attempts and suspicious activities
- **Device Lifecycle**: Track device usage from registration to revocation

### Integration Points
- **Logging**: Structured logs for external SIEM systems
- **Metrics**: Prometheus-compatible metrics for monitoring
- **Events**: Webhook support for real-time security notifications
- **APIs**: Full REST API for custom integrations

## ?? Future Enhancements

### Planned Features
- **Push Notifications**: Real-time QR approval notifications
- **Biometric Integration**: Fingerprint/FaceID support for device approval
- **Risk Scoring**: ML-based risk assessment for authentication attempts
- **Geofencing**: Location-based authentication policies
- **Device Attestation**: Hardware-backed device identity verification

### Integration Opportunities
- **Mobile Apps**: Native iOS/Android apps for device management
- **Browser Extensions**: One-click device registration and management
- **Enterprise Integration**: Active Directory, SCIM, and SSO providers
- **IoT Support**: Specialized workflows for IoT device authentication

## ?? References

- [OpenID Connect Specification](https://openid.net/connect/)
- [ASP.NET Core Identity Documentation](https://docs.microsoft.com/aspnet/core/security/authentication/identity)
- [Entity Framework Core Documentation](https://docs.microsoft.com/ef/core/)
- [Device Flow Specification (RFC 8628)](https://tools.ietf.org/html/rfc8628)

---

**Built with ?? for enterprise security and user experience**