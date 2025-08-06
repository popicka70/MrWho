# Test script for Identity Resources and UserInfo endpoint
# This script demonstrates how identity resources automatically attach claims to the UserInfo response

Write-Host "=== MrWho Identity Resources UserInfo Test ===" -ForegroundColor Cyan
Write-Host ""

# Configuration
$baseUrl = "https://localhost:7113"
$clientId = "postman_client"
$clientSecret = "postman_secret"
$username = "test@example.com"
$password = "Test123!"

# Function to make API calls with error handling
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
        if ($_.Exception.Response) {
            $statusCode = $_.Exception.Response.StatusCode
            Write-Host "Status Code: $statusCode" -ForegroundColor Red
        }
        return $null
    }
}

# Test 1: Basic UserInfo with standard scopes
Write-Host "Test 1: UserInfo with standard scopes (openid, email, profile)" -ForegroundColor Green

$tokenBody = @{
    grant_type = "password"
    client_id = $clientId
    client_secret = $clientSecret
    username = $username
    password = $password
    scope = "openid email profile"
}

$tokenResponse = Invoke-SafeRestMethod -Uri "$baseUrl/connect/token" -Method POST -Body $tokenBody -ContentType "application/x-www-form-urlencoded"

if ($tokenResponse) {
    Write-Host "? Access token obtained successfully" -ForegroundColor Green
    
    $userInfoHeaders = @{
        Authorization = "Bearer $($tokenResponse.access_token)"
    }
    
    $userInfo = Invoke-SafeRestMethod -Uri "$baseUrl/connect/userinfo" -Headers $userInfoHeaders
    
    if ($userInfo) {
        Write-Host "? UserInfo response received:" -ForegroundColor Green
        $userInfo | ConvertTo-Json -Depth 3
        Write-Host ""
        
        # Verify expected claims
        $expectedClaims = @("sub", "email", "email_verified", "name", "preferred_username")
        foreach ($claim in $expectedClaims) {
            if ($userInfo.$claim) {
                Write-Host "? $claim present: $($userInfo.$claim)" -ForegroundColor Green
            } else {
                Write-Host "? $claim missing" -ForegroundColor Red
            }
        }
    }
} else {
    Write-Host "? Failed to obtain access token" -ForegroundColor Red
}

Write-Host ""
Write-Host "----------------------------------------" -ForegroundColor Yellow
Write-Host ""

# Test 2: UserInfo with roles scope
Write-Host "Test 2: UserInfo with roles scope" -ForegroundColor Green

$tokenBodyWithRoles = @{
    grant_type = "password"
    client_id = $clientId
    client_secret = $clientSecret
    username = $username
    password = $password
    scope = "openid email profile roles"
}

$tokenResponseWithRoles = Invoke-SafeRestMethod -Uri "$baseUrl/connect/token" -Method POST -Body $tokenBodyWithRoles -ContentType "application/x-www-form-urlencoded"

if ($tokenResponseWithRoles) {
    Write-Host "? Access token with roles scope obtained" -ForegroundColor Green
    
    $userInfoHeaders = @{
        Authorization = "Bearer $($tokenResponseWithRoles.access_token)"
    }
    
    $userInfoWithRoles = Invoke-SafeRestMethod -Uri "$baseUrl/connect/userinfo" -Headers $userInfoHeaders
    
    if ($userInfoWithRoles) {
        Write-Host "? UserInfo response with roles:" -ForegroundColor Green
        $userInfoWithRoles | ConvertTo-Json -Depth 3
        Write-Host ""
        
        if ($userInfoWithRoles.role) {
            Write-Host "? Roles claim present: $($userInfoWithRoles.role -join ', ')" -ForegroundColor Green
        } else {
            Write-Host "? No roles assigned to user" -ForegroundColor Yellow
        }
    }
}

Write-Host ""
Write-Host "----------------------------------------" -ForegroundColor Yellow
Write-Host ""

# Test 3: Limited scope test (only openid)
Write-Host "Test 3: UserInfo with limited scope (openid only)" -ForegroundColor Green

$tokenBodyLimited = @{
    grant_type = "password"
    client_id = $clientId
    client_secret = $clientSecret
    username = $username
    password = $password
    scope = "openid"
}

$tokenResponseLimited = Invoke-SafeRestMethod -Uri "$baseUrl/connect/token" -Method POST -Body $tokenBodyLimited -ContentType "application/x-www-form-urlencoded"

if ($tokenResponseLimited) {
    Write-Host "? Access token with openid scope only obtained" -ForegroundColor Green
    
    $userInfoHeaders = @{
        Authorization = "Bearer $($tokenResponseLimited.access_token)"
    }
    
    $userInfoLimited = Invoke-SafeRestMethod -Uri "$baseUrl/connect/userinfo" -Headers $userInfoHeaders
    
    if ($userInfoLimited) {
        Write-Host "? UserInfo response (limited scope):" -ForegroundColor Green
        $userInfoLimited | ConvertTo-Json -Depth 3
        Write-Host ""
        
        if ($userInfoLimited.sub) {
            Write-Host "? Subject claim present (expected)" -ForegroundColor Green
        }
        
        if ($userInfoLimited.email) {
            Write-Host "? Email claim present (should not be with openid scope only)" -ForegroundColor Yellow
        } else {
            Write-Host "? Email claim correctly excluded (no email scope requested)" -ForegroundColor Green
        }
    }
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Test Summary:" -ForegroundColor Cyan
Write-Host "• Identity resources are working if claims appear/disappear based on requested scopes" -ForegroundColor White
Write-Host "• The UserInfo endpoint should return different claims for different scope requests" -ForegroundColor White
Write-Host "• Check the admin interface to create custom identity resources for testing" -ForegroundColor White
Write-Host "========================================" -ForegroundColor Cyan