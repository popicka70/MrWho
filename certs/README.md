Developer HTTPS certificate for Docker

1) Create/Export dev cert (PowerShell):
   - dotnet dev-certs https --clean
   - dotnet dev-certs https -ep "$Env:USERPROFILE\.aspnet\https\aspnetapp.pfx" -p "<password>"

2) Create .env from .env.example and set:
   - ASPNETCORE_Kestrel__Certificates__Default__Password=<password>
   - LOCAL_HTTPS_CERT_DIR=C:\Users\<you>\.aspnet\https

3) Verify the file exists:
   - C:\Users\<you>\.aspnet\https\aspnetapp.pfx

Notes
- Containers listen on 8080 (HTTP) and 8443 (HTTPS)
- Compose maps to host ports:
  - MrWho: 7112->8080, 7113->8443
  - Admin: 7256->8080, 7257->8443
- For local browser use https://localhost:7113 (OIDC) and https://localhost:7257 (Admin)
