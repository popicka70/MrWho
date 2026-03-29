# Platform Admin Guide

Last updated: 2026-03-29

Platform administration is the cross-tenant management surface of MrWhoOidc.

## What Platform Admins Manage

Platform admins are responsible for:

- tenant provisioning
- tenant lifecycle changes
- tenant import and export
- impersonation into tenant admin contexts
- platform settings and license visibility

This is distinct from tenant administration.

## Typical Workflows

### Create a tenant

A platform admin creates the tenant and seeds its initial admin access. This can be done through the UI or through `mrwho-cli tenant create`.

### Inspect tenant state

Platform admins review tenant lists, status, and limits before handing off daily operations to tenant admins.

### Impersonate a tenant admin context

Impersonation exists for controlled troubleshooting and administration. Use it sparingly and treat it as a privileged action.

### Import and export

Tenant configuration can be exported for migration or backup workflows and imported into another environment after preview.

## Recommended Practices

- keep platform-admin accounts separate from tenant-admin accounts
- use platform admin only for cross-tenant or platform-scoped tasks
- prefer export preview and import preview before applying changes in production
- audit impersonation and tenant lifecycle actions regularly

## CLI Examples

```bash
mrwho-cli tenant list
mrwho-cli tenant get acme
mrwho-cli export tenant acme --mode obfuscated --output ./exports
mrwho-cli license show
```

## Multi-Tenancy Relationship

Multi-tenancy is license-controlled. When it is active:

- tenants expose tenant-scoped issuers under `/t/{slug}`
- tenant admins work inside that tenant scope
- platform admins remain the cross-tenant control plane
