# Public Website Install Review - 2026-05

This note captures concrete copy changes proposed after a clean-room install test that followed the public `www.mrwhooidc.com` setup path from the homepage to the prebuilt Docker guide.

## Summary

The public setup flow works end to end for a fresh local Docker install, but the operator experience can be made clearer by tightening the first-run instructions around working-directory choice, the actual minimum `.env` edits, Linux certificate permissions, and browser expectations for the self-signed local certificate.

The public `getting-started.html` source was not present in this repository snapshot, so the items below are phrased as copy proposals for the website owner to apply where that page is maintained.

## Homepage Proposals

- Make `Prebuilt Docker install` the explicit primary CTA for first-time evaluators.
- Keep `Build from source` visually secondary and clearly scoped to contributors.
- Add one short sentence near the CTA explaining the first-run path: clone `MrWho`, generate the local certificate, set `POSTGRES_PASSWORD` and a temporary `BOOTSTRAP_TOKEN`, then bootstrap the default tenant.

## Getting Started Page Proposals

- In the work-folder step, say what to do if `$HOME/src/MrWho` already exists: either intentionally reuse it or choose a different persistent directory for a clean evaluation.
- In the certificate step, keep `chmod 644 ./certs/aspnetapp.pfx` inline for Linux/macOS instead of only as a side note.
- In the `.env` step, say explicitly that the stock local path only requires changing `POSTGRES_PASSWORD` and `BOOTSTRAP_TOKEN` for a fresh install. `CERT_PASSWORD=changeit` and `OIDC_PUBLIC_BASE_URL=https://localhost:8443` already match the generated certificate and default ports.
- Remove or refresh the note about expected `MAIL_*` compose warnings. The current local run did not produce them with the published template.
- Add a browser note before the Admin UI step: opening `https://localhost:8443/admin` in a browser will show a self-signed certificate warning until the user trusts the generated local certificate.
- Keep the existing bootstrap retry note, but phrase it as a normal first-run wait: HTTPS can take a few extra seconds to bind after `docker compose up -d`.

## Troubleshooting Copy Proposal

- Add the exact missing-cert startup log to the quick troubleshooting section:

```text
Configured HTTPS certificate file '/https/aspnetapp.pfx' was not found
```

- Follow it immediately with the fix sequence:

```bash
bash ./scripts/generate-cert.sh localhost changeit
chmod 644 ./certs/aspnetapp.pfx
docker compose up -d
```

## Product Log Noise Worth Reducing

These items did not block installation, but they make a healthy first run look less stable than it is:

- `Tenant context required` during key-cache warmup
- `Overriding HTTP_PORTS ... Binding to values defined by URLS` on every startup
- ordinary tenant-tracking requests logged at warning level
- EF query warning for `First` / `FirstOrDefault` without ordering

If these remain expected, they should be downgraded or removed so operators do not confuse them with a failed deployment.