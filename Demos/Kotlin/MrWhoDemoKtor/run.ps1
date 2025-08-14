Param(
    [string]$Authority = "https://mrwho-production.up.railway.app",
    [string]$ClientId = "demo.web",
    [string]$ClientSecret = "dev-secret",
    [string]$RedirectUrl = "http://localhost:8085/callback",
    [string]$PostLogoutRedirectUrl = "http://localhost:8085/"
)

$env:MRWHO_AUTHORITY = $Authority
$env:MRWHO_CLIENT_ID = $ClientId
$env:MRWHO_CLIENT_SECRET = $ClientSecret
$env:MRWHO_REDIRECT_URL = $RedirectUrl
$env:MRWHO_POST_LOGOUT_REDIRECT_URL = $PostLogoutRedirectUrl

# Use gradle wrapper if present, else fall back to gradle
if (Test-Path ./gradlew.bat) { ./gradlew.bat run } else { gradle.bat run }
