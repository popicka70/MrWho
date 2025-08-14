# MrWhoDemoKtor (Kotlin/Ktor OIDC Web Demo)

A minimal Ktor web app demonstrating OIDC login against your MrWho server using the Authorization Code flow.

## Prereqs
- JDK 21+
- Gradle (wrapper can be added later) or use IntelliJ's Gradle support
- MrWho OIDC server running locally or accessible

## Configure
Set environment variables (recommended):

- MRWHO_AUTHORITY = https://localhost:7113
- MRWHO_CLIENT_ID = demo.web
- MRWHO_CLIENT_SECRET = dev-secret
- MRWHO_REDIRECT_URL = http://localhost:8085/callback
- MRWHO_POST_LOGOUT_REDIRECT_URL = http://localhost:8085/

Ensure the client in MrWho has redirect URI and post-logout redirect URI configured accordingly.

## Run
From this folder, either use a local Gradle installation or run from IntelliJ IDEA:

```powershell
# Windows PowerShell (local Gradle)
$env:MRWHO_AUTHORITY = "https://localhost:7113"; $env:MRWHO_CLIENT_ID = "demo.web"; $env:MRWHO_CLIENT_SECRET = "dev-secret"; $env:MRWHO_REDIRECT_URL = "http://localhost:8085/callback"; $env:MRWHO_POST_LOGOUT_REDIRECT_URL = "http://localhost:8085/"; gradle.bat run
```

Or open the project in IntelliJ IDEA, trust the Gradle build, and run the "run" task.

Then open http://localhost:8085 and click "Sign in with MrWho".

## Notes
- Discovery uses the correct OIDC path: `/.well-known/openid-configuration` (hyphen, not underscore).
- Session is cookie-based and stores tokens for demo purposes only. Do not store tokens in cookies in production.
- HTTPS recommended; cookie Secure=false here for local demo.
