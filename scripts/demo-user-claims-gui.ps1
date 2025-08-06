# User Claims Management Demo Script
# This script demonstrates the complete User Claims Management GUI functionality

Write-Host "=== MrWho User Claims Management Demo ===" -ForegroundColor Cyan
Write-Host "This script demonstrates the complete user claims management system" -ForegroundColor Green
Write-Host ""

# Configuration
$baseUrl = "https://localhost:7113"
$clientId = "postman_client"
$clientSecret = "postman_secret"
$username = "test@example.com"
$password = "Test123!"

Write-Host "Demo Configuration:" -ForegroundColor Yellow
Write-Host "  API Base URL: $baseUrl" -ForegroundColor White
Write-Host "  Test User: $username" -ForegroundColor White
Write-Host "  Admin Interface: https://localhost:7257" -ForegroundColor White
Write-Host ""

# Function to make API calls safely
function Invoke-SafeRestMethod {
    param(
        [string]$Uri,
        [string]$Method = "GET",
        [hashtable]$Headers = @{},
        [object]$Body = $null,
        [string]$ContentType = "application/json"
    )
    
    try {
        if ($Body -ne $null) {
            return Invoke-RestMethod -Uri $Uri -Method $Method -Headers $Headers -Body $Body -ContentType $ContentType
        } else {
            return Invoke-RestMethod -Uri $Uri -Method $Method -Headers $Headers
        }
    }
    catch {
        Write-Host "API call failed: $($_.Exception.Message)" -ForegroundColor Red
        return $null
    }
}

# Demo Step 1: Test Basic Authentication
Write-Host "Step 1: Testing Basic Authentication" -ForegroundColor Green
Write-Host "Getting access token with basic scopes..." -ForegroundColor White

$basicTokenBody = @{
    grant_type = "password"
    client_id = $clientId
    client_secret = $clientSecret
    username = $username
    password = $password
    scope = "openid email profile"
}

$basicToken = Invoke-SafeRestMethod -Uri "$baseUrl/connect/token" -Method POST -Body $basicTokenBody -ContentType "application/x-www-form-urlencoded"

if ($basicToken) {
    Write-Host "? Basic authentication successful" -ForegroundColor Green
    
    $userInfoHeaders = @{ Authorization = "Bearer $($basicToken.access_token)" }
    $basicUserInfo = Invoke-SafeRestMethod -Uri "$baseUrl/connect/userinfo" -Headers $userInfoHeaders
    
    if ($basicUserInfo) {
        Write-Host "? Basic UserInfo response received:" -ForegroundColor Green
        $basicUserInfo | ConvertTo-Json -Depth 2
        Write-Host ""
    }
} else {
    Write-Host "? Basic authentication failed" -ForegroundColor Red
    exit 1
}

Write-Host "---" -ForegroundColor Yellow
Write-Host ""

# Demo Step 2: Demonstrate Custom Claims (if they exist)
Write-Host "Step 2: Testing Custom Claims (if configured)" -ForegroundColor Green
Write-Host "This demonstrates how claims added via the admin GUI appear in UserInfo..." -ForegroundColor White

$customTokenBody = @{
    grant_type = "password"
    client_id = $clientId
    client_secret = $clientSecret
    username = $username
    password = $password
    scope = "openid email profile custom_profile"
}

$customToken = Invoke-SafeRestMethod -Uri "$baseUrl/connect/token" -Method POST -Body $customTokenBody -ContentType "application/x-www-form-urlencoded"

if ($customToken) {
    Write-Host "? Custom scope token obtained" -ForegroundColor Green
    
    $userInfoHeaders = @{ Authorization = "Bearer $($customToken.access_token)" }
    $customUserInfo = Invoke-SafeRestMethod -Uri "$baseUrl/connect/userinfo" -Headers $userInfoHeaders
    
    if ($customUserInfo) {
        Write-Host "? UserInfo with custom scopes:" -ForegroundColor Green
        $customUserInfo | ConvertTo-Json -Depth 2
        
        # Check for custom claims
        $customClaims = @()
        foreach ($property in $customUserInfo.PSObject.Properties) {
            if ($property.Name -notin @("sub", "email", "email_verified", "name", "preferred_username")) {
                $customClaims += "$($property.Name): $($property.Value)"
            }
        }
        
        if ($customClaims.Count -gt 0) {
            Write-Host ""
            Write-Host "?? Custom claims found:" -ForegroundColor Magenta
            foreach ($claim in $customClaims) {
                Write-Host "  • $claim" -ForegroundColor Cyan
            }
        } else {
            Write-Host ""
            Write-Host "? No custom claims configured yet." -ForegroundColor Yellow
            Write-Host "  Add claims via: https://localhost:7257/users/edit" -ForegroundColor Yellow
        }
        Write-Host ""
    }
}

Write-Host "---" -ForegroundColor Yellow
Write-Host ""

# Demo Step 3: Show Admin Interface Instructions
Write-Host "Step 3: Admin Interface Guide" -ForegroundColor Green
Write-Host ""
Write-Host "?? User Claims Management GUI Features:" -ForegroundColor Cyan
Write-Host ""
Write-Host "1. Navigate to: https://localhost:7257/users" -ForegroundColor White
Write-Host "2. Click 'Edit' on any user" -ForegroundColor White
Write-Host "3. Go to 'Claims' tab" -ForegroundColor White
Write-Host "4. Add claims using the dropdown or custom input" -ForegroundColor White
Write-Host ""

Write-Host "?? Available Predefined Claims:" -ForegroundColor Cyan
$predefinedClaims = @(
    "given_name - First name of the user",
    "family_name - Last name of the user", 
    "department - User's department or division",
    "job_title - User's job title or position",
    "employee_id - Unique employee identifier",
    "manager_email - Email of the user's manager",
    "office_location - Physical office location",
    "hire_date - Date the user was hired",
    "preferred_language - User's preferred interface language",
    "timezone - User's preferred timezone"
)

foreach ($claim in $predefinedClaims) {
    Write-Host "  • $claim" -ForegroundColor White
}

Write-Host ""
Write-Host "?? Identity Resources Configuration:" -ForegroundColor Cyan
Write-Host "1. Navigate to: https://localhost:7257/identity-resources" -ForegroundColor White
Write-Host "2. Create new identity resource (e.g., 'company_profile')" -ForegroundColor White
Write-Host "3. Add claim types that should be included" -ForegroundColor White
Write-Host "4. Enable the resource" -ForegroundColor White
Write-Host ""

Write-Host "?? Testing Workflow:" -ForegroundColor Cyan
Write-Host "1. Add claims to user via Claims Management GUI" -ForegroundColor White
Write-Host "2. Create identity resource with those claim types" -ForegroundColor White
Write-Host "3. Request token with the identity resource scope" -ForegroundColor White
Write-Host "4. Call UserInfo - claims appear automatically!" -ForegroundColor White
Write-Host ""

# Demo Step 4: Show Sample Claims to Add
Write-Host "Step 4: Sample Claims for Testing" -ForegroundColor Green
Write-Host ""
Write-Host "Try adding these sample claims to test users:" -ForegroundColor Cyan
Write-Host ""

$sampleClaims = @(
    @{ Type = "department"; Value = "Engineering"; Description = "User's department" },
    @{ Type = "job_title"; Value = "Senior Developer"; Description = "User's job title" },
    @{ Type = "employee_id"; Value = "EMP001"; Description = "Employee identifier" },
    @{ Type = "office_location"; Value = "New York"; Description = "Office location" },
    @{ Type = "manager_email"; Value = "manager@company.com"; Description = "Manager's email" },
    @{ Type = "hire_date"; Value = "2024-01-15"; Description = "Date hired" },
    @{ Type = "preferred_language"; Value = "en-US"; Description = "Preferred language" },
    @{ Type = "timezone"; Value = "America/New_York"; Description = "User's timezone" }
)

foreach ($claim in $sampleClaims) {
    Write-Host "  ?? $($claim.Type): $($claim.Value)" -ForegroundColor Yellow
    Write-Host "     $($claim.Description)" -ForegroundColor Gray
}

Write-Host ""
Write-Host "?? Quick Test Identity Resource:" -ForegroundColor Cyan
Write-Host "  Name: company_profile" -ForegroundColor White
Write-Host "  Claims: department, job_title, employee_id, office_location" -ForegroundColor White
Write-Host "  Test Scope: 'openid email profile company_profile'" -ForegroundColor White
Write-Host ""

# Demo Step 5: Final Summary
Write-Host "=== Demo Complete ===" -ForegroundColor Cyan
Write-Host ""
Write-Host "? Key Features Demonstrated:" -ForegroundColor Green
Write-Host "  • Enhanced UserInfo endpoint with dynamic claims" -ForegroundColor White
Write-Host "  • User Claims Management GUI" -ForegroundColor White
Write-Host "  • Identity Resources integration" -ForegroundColor White
Write-Host "  • Scope-based claim filtering" -ForegroundColor White
Write-Host ""
Write-Host "?? Next Steps:" -ForegroundColor Cyan
Write-Host "  1. Open admin interface: https://localhost:7257" -ForegroundColor White
Write-Host "  2. Add claims to users via Claims tab" -ForegroundColor White
Write-Host "  3. Configure identity resources" -ForegroundColor White
Write-Host "  4. Test with different scopes" -ForegroundColor White
Write-Host ""
Write-Host "?? Documentation:" -ForegroundColor Cyan
Write-Host "  • docs/user-claims-management-gui-guide.md" -ForegroundColor White
Write-Host "  • docs/identity-resources-id-token-guide.md" -ForegroundColor White
Write-Host ""
Write-Host "?? User Claims Management GUI is ready for use!" -ForegroundColor Magenta