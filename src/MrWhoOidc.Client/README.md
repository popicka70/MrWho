# MrWhoOidc.Client

`MrWhoOidc.Client` is the .NET helper package for integrating applications with the MrWhoOidc server.

It includes helpers for:

- discovery and metadata caching
- JWKS caching for token validation
- authorization code and PKCE flows
- client credentials and token exchange
- JAR/JARM integration support
- front-channel and back-channel logout helpers

## Targets

- `net8.0`
- `net10.0`

## Getting Started

```csharp
var builder = WebApplication.CreateBuilder(args);

builder.Services.AddMrWhoOidcClient(builder.Configuration, sectionName: "MrWhoOidc:Client");
```

For server-side integration details, see [docs/developer-guide.md](docs/developer-guide.md) and [docs/advanced-flows-guide.md](docs/advanced-flows-guide.md).
