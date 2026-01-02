# OBO Demo API

A minimal .NET 10 Web API that demonstrates On-Behalf-Of (OBO) token validation.

## Purpose

This API is designed to be called by the `dotnet-mvc-demo` client using an access token obtained via the Token Exchange grant (RFC 8693). It validates the token and returns information about the subject (user) and the actor (the calling client).

## Endpoints

- `GET /me` - Returns JSON with subject, actor, and scope information. Requires a valid Bearer token.
- `GET /health` - Health check endpoint.

## Configuration

Configured via `appsettings.json` or environment variables:

- `MrWhoOidc:Issuer`: The OIDC provider URL (e.g., `https://mrwho.local:9443`)
- `MrWhoOidc:Audience`: The expected audience claim (default: `obo-demo-api`)
