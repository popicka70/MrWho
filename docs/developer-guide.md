# MrWhoOidc Developer Guide

Last updated: 2026-03-29

This guide is for application developers integrating with an MrWhoOidc deployment.

## Issuer Patterns

Single-tenant style:

```text
https://auth.example.com
```

Tenant-scoped style:

```text
https://auth.example.com/t/acme
```

The tenant-scoped issuer is the most important pattern to keep in mind when multi-tenancy is active.

## Core Endpoints

| Endpoint | Purpose |
|---|---|
| `/.well-known/openid-configuration` | discovery document |
| `/authorize` | interactive authorization endpoint |
| `/token` | token issuance |
| `/userinfo` | user claims |
| `/jwks` | signing keys |
| `/revocation` | token revocation |
| `/introspect` | token introspection |
| `/par` | pushed authorization requests |
| `/device` | device authorization verification UX |
| `/device-authorization` | device authorization grant initiation |
| `/backchannel-authentication` | CIBA initiation |
| `/logout` | logout |

Tenant-scoped deployments expose the same endpoints below `/t/{slug}`.

## Supported Flows

- Authorization Code + PKCE
- Client Credentials
- Token Exchange / on-behalf-of
- Refresh token rotation
- Device Authorization (RFC 8628)
- CIBA
- DPoP for token-bound requests
- PAR, JAR, and JARM

## Authorization Code + PKCE

This remains the recommended default for interactive browser and server-side web apps.

If the server advertises PAR, public and confidential clients can push the request first and then call `/authorize` with the returned `request_uri`.

## Token Exchange / OBO

MrWhoOidc supports token exchange for on-behalf-of scenarios. In practice, the pattern is:

1. the user signs in to an interactive client
2. that client receives an access token for itself
3. the client exchanges that token for a downstream API audience
4. the downstream API inspects the resulting claims, including actor context

See the sample API in `../demos/obo-demo-api`.

## PAR, JAR, and JARM

- PAR is available through `/par`
- JAR request objects can be provided through `request`
- JARM response modes such as `query.jwt` are supported for clients that opt in

See `advanced-flows-guide.md` for the current operational notes.

## DPoP

DPoP can be used for token requests and APIs that require proof-of-possession semantics.

Practical guidance:

- treat DPoP as an advanced security feature, not a default for every client
- make sure the resource server validates DPoP when it is part of the contract
- use Redis-backed replay protection in larger deployments

## Device Authorization and CIBA

MrWhoOidc now supports non-browser and decoupled authentication flows:

- Device Authorization for TVs, consoles, and limited-input devices
- CIBA for decoupled approval flows

See `advanced-flows-guide.md` for current public guidance.

## Logout

MrWhoOidc supports front-channel and back-channel logout patterns. Back-channel logout notifications are delivered through a durable outbox/background dispatcher model.

## Recommended Public References

- `.NET client package README`
- `demos/dotnet-mvc-client/README.md`
- `demos/react-client/README.md`
- `demos/go-client/README.md`
- `mrwho-cli-guide.md`
