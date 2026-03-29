# WebAuthn and Passkeys Guide

Last updated: 2026-03-29

MrWhoOidc supports WebAuthn-based authentication for passkeys and security keys.

## What WebAuthn Is Used For

WebAuthn can be used to:

- strengthen MFA
- reduce password dependence
- improve administrator and end-user sign-in security
- support passkeys on modern browsers and operating systems

## Operational Requirements

Before enabling WebAuthn, verify:

- the public HTTPS origin is stable
- the relying party ID matches the deployed host model
- reverse proxy settings preserve the public host and scheme correctly
- browsers and authenticators used by your audience support passkeys or WebAuthn security keys

## Deployment Notes

WebAuthn is sensitive to origin and RP ID mismatches.

Practical guidance:

- use a stable public hostname
- avoid switching between multiple hostnames for the same deployment
- validate forwarded-header configuration when running behind a proxy
- test registration and assertion flows in the exact environment users will use

## User Experience Guidance

For public deployments, describe WebAuthn in plain language:

- “Passkey” for platform authenticators
- “Security key” for roaming authenticators

Plan for:

- passkey enrollment guidance
- fallback sign-in methods
- recovery workflows when a device is lost

## Administrative Guidance

Administrators should treat WebAuthn as a security feature rollout, not just a toggle.

Recommended steps:

1. enable it in a non-production environment first
2. validate browser/device coverage for your user base
3. define recovery and support workflows
4. communicate the user-facing terminology before rollout

## Security Notes

- require HTTPS in every real deployment
- avoid origin rewriting at the proxy layer
- validate that the final public host matches what users see in the browser
- test account recovery before enabling passkeys broadly
