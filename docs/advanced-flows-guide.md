# Advanced Flows Guide

Last updated: 2026-03-29

This guide summarizes the more advanced OAuth 2.0 and OpenID Connect capabilities currently exposed by MrWhoOidc.

## PAR

Pushed Authorization Requests move sensitive authorization parameters off the browser URL.

Operationally:

- client posts the request to `/par`
- server returns a `request_uri`
- client redirects the browser to `/authorize` with that `request_uri`

Use PAR when:

- request payloads are large
- you want better integrity around authorization requests
- upstream or policy requires it

## JAR

JWT Secured Authorization Requests let the client sign the authorization request as a request object.

Use JAR when:

- you need signed request semantics
- you want stronger parameter integrity than plain query parameters
- the client already manages signing keys reliably

## JARM

JWT Secured Authorization Response Mode signs the authorization response.

Current public guidance:

- use JARM only for clients that explicitly require it
- validate `iss`, `aud`, `exp`, and signature on the client side
- keep the client-side validation logic simple and deterministic

## DPoP

Demonstrating Proof-of-Possession binds a token to a client-held key.

Use DPoP when:

- the resource server is prepared to validate DPoP proofs
- bearer-token replay risk matters
- you control both the client and the protected API contracts

Operational notes:

- DPoP is stronger than bearer tokens but also operationally stricter
- proof validation and replay protection must exist on the API side too
- Redis-backed replay protection is recommended for larger deployments

## Device Authorization

Device Authorization is appropriate for:

- TVs
- kiosks
- consoles
- devices with limited text input

Flow summary:

1. device requests codes from `/device-authorization`
2. user completes verification through the browser UX
3. device polls `/token` until approval completes

## CIBA

CIBA supports decoupled authentication where the approval happens on a different device or channel.

Use CIBA when:

- the user is not expected to authenticate in the same browser session
- approval occurs in a mobile or back-office experience
- the client can manage asynchronous authentication state

## Token Exchange / OBO

Token exchange is the basis for on-behalf-of scenarios.

Typical pattern:

- front-end client obtains an access token
- that token is exchanged for a downstream audience
- the downstream API receives a narrowed or redirected token for its own audience

Use it when one service calls another on behalf of the signed-in user.

## Back-Channel Logout

Back-channel logout lets the identity provider notify relying parties directly.

Operationally, MrWhoOidc uses a durable outbox and background dispatcher so transient delivery failures can be retried.

## Recommendation

Do not enable every advanced feature by default. Prefer the smallest feature set that meets the client or security requirement, then add PAR, JAR, JARM, DPoP, Device Authorization, or CIBA intentionally per client integration.
