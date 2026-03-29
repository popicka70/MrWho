# mrwho-cli Guide

Last updated: 2026-03-29

`mrwho-cli` is the command-line administration tool for MrWhoOidc.

## Authentication Model

The CLI uses device-code login and stores tokens in named profiles.

Login to a tenant-scoped server:

```bash
mrwho-cli login --server https://auth.example.com/t/default
```

Typical profile operations:

```bash
mrwho-cli profile list
mrwho-cli profile show
mrwho-cli profile switch my-prod
mrwho-cli logout
```

## Output Formats

Most read operations support:

- `--format Table`
- `--format Json`
- `--format Yaml`

Example:

```bash
mrwho-cli client list --format Json
```

## Common Workflows

### Discover a server

```bash
mrwho-cli discovery --server https://auth.example.com/t/default
```

### Create a tenant

Platform-admin profile required:

```bash
mrwho-cli tenant create \
  --slug acme \
  --name "Acme Corp" \
  --admin-email admin@acme.com \
  --admin-password "ChangeMe123!"
```

### Create a client

```bash
mrwho-cli client create \
  --client-id my-app \
  --client-name "My Application" \
  --realm-id <realm-guid> \
  --scope "openid profile email" \
  --grant-types "authorization_code refresh_token" \
  --redirect-uris "https://app.example.com/callback" \
  --require-pkce \
  --create-initial-secret \
  --output ./my-app-secret.json
```

### Create a user

```bash
mrwho-cli user create \
  --username alice \
  --email alice@example.com \
  --name "Alice Smith" \
  --password "ChangeMe123!" \
  --output ./alice.json
```

### Rotate a client secret

```bash
mrwho-cli client rotate-secret <client-guid> \
  --expires-in-days 90 \
  --revoke-oldest \
  --output ./new-secret.json \
  --confirm
```

### Export and import

```bash
mrwho-cli export tenant acme --mode obfuscated --output ./exports
mrwho-cli import preview ./exports/acme-manifest.json
mrwho-cli import apply ./exports/acme-manifest.json --conflict-resolution overwrite
```

## Operations and Diagnostics

Useful commands for live environments:

```bash
mrwho-cli whoami
mrwho-cli health
mrwho-cli audit list
mrwho-cli bcl alerts
mrwho-cli rate-limits overview
mrwho-cli license show
```

## Safety Notes

- write operations support `--dry-run` where available
- secret values are written to files, not printed to the terminal
- platform-admin commands require a platform-admin profile
- tenant-scoped logins should include `/t/<slug>` in the server URL
