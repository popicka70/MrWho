# Kotlin Spring Boot Demo Client

This demo proves MrWhoOidc works great outside of .NET by using **Kotlin + Spring Boot**.

It supports:

- **Interactive login** (OIDC Authorization Code + PKCE) via Spring Security
- **OBO (token exchange)**: exchange the signed-in user's access token for an API token
- **M2M (client_credentials)**: acquire a machine token and call the same API endpoint

## Run with the demo stack

From the repo root:

```powershell
docker compose -f MrWho/demos/docker-compose.yml up -d --build
```

Then open:

- App: http://localhost:5090
- Token comparison page: http://localhost:5090/token-comparison (requires sign-in)

## Notes

- The demo stack uses `https://mrwho.local:9443` as the issuer.
- The container imports the demo TLS cert (`MrWhoOidc/certs/aspnetapp.pfx`) into the JVM truststore so Spring can fetch discovery/JWKS over HTTPS.
