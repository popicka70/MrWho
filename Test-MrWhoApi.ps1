# MrWho OIDC API Test Script
# This script demonstrates how to interact with the MrWho OIDC service

param(
    [string]$BaseUrl = "https://localhost:7001",
    [string]$ClientId = "mrwho-client",
    [string]$ClientSecret = "mrwho-secret",
    [string]$Username = "admin@mrwho.com",
    [string]$Password = "Admin123!"
)

Write-Host "MrWho OIDC API Test Script" -ForegroundColor Green
Write-Host "Base URL: $BaseUrl" -ForegroundColor Yellow
Write-Host ""

# Function to get access token
function Get-AccessToken {
    param($BaseUrl, $ClientId, $ClientSecret, $Username, $Password)
    
    Write-Host "1. Getting access token..." -ForegroundColor Cyan
    
    $tokenUrl = "$BaseUrl/connect/token"
    $body = @{
        grant_type = "password"
        client_id = $ClientId
        client_secret = $ClientSecret
        username = $Username
        password = $Password
        scope = "email profile"
    }
    
    try {
        $response = Invoke-RestMethod -Uri $tokenUrl -Method Post -Body $body -ContentType "application/x-www-form-urlencoded"
        Write-Host "? Token obtained successfully" -ForegroundColor Green
        Write-Host "Token Type: $($response.token_type)" -ForegroundColor Gray
        Write-Host "Expires In: $($response.expires_in) seconds" -ForegroundColor Gray
        Write-Host "Scope: $($response.scope)" -ForegroundColor Gray
        Write-Host ""
        return $response.access_token
    }
    catch {
        Write-Host "? Failed to get token: $($_.Exception.Message)" -ForegroundColor Red
        return $null
    }
}

# Function to test public endpoint
function Test-PublicEndpoint {
    param($BaseUrl)
    
    Write-Host "2. Testing public endpoint..." -ForegroundColor Cyan
    
    $url = "$BaseUrl/api/test/public"
    
    try {
        $response = Invoke-RestMethod -Uri $url -Method Get
        Write-Host "? Public endpoint accessible" -ForegroundColor Green
        Write-Host "Message: $($response.message)" -ForegroundColor Gray
        Write-Host ""
        return $true
    }
    catch {
        Write-Host "? Failed to access public endpoint: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

# Function to test protected endpoint
function Test-ProtectedEndpoint {
    param($BaseUrl, $AccessToken)
    
    Write-Host "3. Testing protected endpoint..." -ForegroundColor Cyan
    
    if (-not $AccessToken) {
        Write-Host "? No access token available" -ForegroundColor Red
        return $false
    }
    
    $url = "$BaseUrl/api/test/protected"
    $headers = @{
        Authorization = "Bearer $AccessToken"
    }
    
    try {
        $response = Invoke-RestMethod -Uri $url -Method Get -Headers $headers
        Write-Host "? Protected endpoint accessible" -ForegroundColor Green
        Write-Host "User ID: $($response.user.id)" -ForegroundColor Gray
        Write-Host "Username: $($response.user.username)" -ForegroundColor Gray
        Write-Host "Email: $($response.user.email)" -ForegroundColor Gray
        Write-Host ""
        return $true
    }
    catch {
        Write-Host "? Failed to access protected endpoint: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

# Function to get user info
function Get-UserInfo {
    param($BaseUrl, $AccessToken)
    
    Write-Host "4. Getting user info..." -ForegroundColor Cyan
    
    if (-not $AccessToken) {
        Write-Host "? No access token available" -ForegroundColor Red
        return $false
    }
    
    $url = "$BaseUrl/api/test/user-info"
    $headers = @{
        Authorization = "Bearer $AccessToken"
    }
    
    try {
        $response = Invoke-RestMethod -Uri $url -Method Get -Headers $headers
        Write-Host "? User info retrieved" -ForegroundColor Green
        Write-Host "Subject: $($response.subject)" -ForegroundColor Gray
        Write-Host "Email: $($response.email)" -ForegroundColor Gray
        Write-Host "Name: $($response.name)" -ForegroundColor Gray
        Write-Host "Role: $($response.role)" -ForegroundColor Gray
        Write-Host ""
        return $true
    }
    catch {
        Write-Host "? Failed to get user info: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

# Function to test user management
function Test-UserManagement {
    param($BaseUrl, $AccessToken)
    
    Write-Host "5. Testing user management..." -ForegroundColor Cyan
    
    $url = "$BaseUrl/api/users"
    
    try {
        $response = Invoke-RestMethod -Uri $url -Method Get
        Write-Host "? User list retrieved" -ForegroundColor Green
        Write-Host "Total users: $($response.Count)" -ForegroundColor Gray
        
        if ($response.Count -gt 0) {
            Write-Host "First user: $($response[0].email)" -ForegroundColor Gray
        }
        Write-Host ""
        return $true
    }
    catch {
        Write-Host "? Failed to get user list: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

# Function to create test user
function New-TestUser {
    param($BaseUrl)
    
    Write-Host "6. Creating test user..." -ForegroundColor Cyan
    
    $url = "$BaseUrl/api/users"
    $testUser = @{
        email = "test.user@example.com"
        password = "TestUser123!"
        firstName = "Test"
        lastName = "User"
        userName = "testuser"
    }
    
    try {
        $response = Invoke-RestMethod -Uri $url -Method Post -Body ($testUser | ConvertTo-Json) -ContentType "application/json"
        Write-Host "? Test user created successfully" -ForegroundColor Green
        Write-Host "User ID: $($response.id)" -ForegroundColor Gray
        Write-Host "Email: $($response.email)" -ForegroundColor Gray
        Write-Host ""
        return $response.id
    }
    catch {
        if ($_.Exception.Response.StatusCode -eq 400) {
            Write-Host "! Test user may already exist" -ForegroundColor Yellow
        } else {
            Write-Host "? Failed to create test user: $($_.Exception.Message)" -ForegroundColor Red
        }
        return $null
    }
}

# Main execution
Write-Host "Starting API tests..." -ForegroundColor Yellow
Write-Host ""

# Test public endpoint first (no auth required)
$publicTest = Test-PublicEndpoint -BaseUrl $BaseUrl

# Get access token
$accessToken = Get-AccessToken -BaseUrl $BaseUrl -ClientId $ClientId -ClientSecret $ClientSecret -Username $Username -Password $Password

# Test protected endpoints
if ($accessToken) {
    $protectedTest = Test-ProtectedEndpoint -BaseUrl $BaseUrl -AccessToken $accessToken
    $userInfoTest = Get-UserInfo -BaseUrl $BaseUrl -AccessToken $accessToken
}

# Test user management
$userMgmtTest = Test-UserManagement -BaseUrl $BaseUrl -AccessToken $accessToken

# Create test user
$testUserId = New-TestUser -BaseUrl $BaseUrl

# Summary
Write-Host "Test Summary:" -ForegroundColor Yellow
Write-Host "Public Endpoint: $(if($publicTest) {'? PASS'} else {'? FAIL'})" -ForegroundColor $(if($publicTest) {'Green'} else {'Red'})
Write-Host "Token Generation: $(if($accessToken) {'? PASS'} else {'? FAIL'})" -ForegroundColor $(if($accessToken) {'Green'} else {'Red'})

if ($accessToken) {
    Write-Host "Protected Endpoint: $(if($protectedTest) {'? PASS'} else {'? FAIL'})" -ForegroundColor $(if($protectedTest) {'Green'} else {'Red'})
    Write-Host "User Info: $(if($userInfoTest) {'? PASS'} else {'? FAIL'})" -ForegroundColor $(if($userInfoTest) {'Green'} else {'Red'})
}

Write-Host "User Management: $(if($userMgmtTest) {'? PASS'} else {'? FAIL'})" -ForegroundColor $(if($userMgmtTest) {'Green'} else {'Red'})
Write-Host "Test User Creation: $(if($testUserId) {'? PASS'} else {'! SKIP'})" -ForegroundColor $(if($testUserId) {'Green'} else {'Yellow'})

Write-Host ""
Write-Host "Test completed!" -ForegroundColor Green