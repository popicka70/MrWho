# GitHub Copilot Instructions

## Development Environment
- **Operating System**: Windows
- **IDE**: Visual Studio 2022
- **Terminal**: Visual Studio 2022 Developer PowerShell v17.14.10
- **Framework**: .NET 9
- **Project Type**: ASP.NET Core Razor Pages with OpenIddict OIDC Server

## Terminal Commands
When executing terminal commands, use the correct PowerShell syntax for Visual Studio 2022 Developer PowerShell v17.14.10. Examples:
**CRITICAL: Always append `; echo ""` to PowerShell commands when using `run_in_terminal`**

- Use `dotnet` commands for .NET operations
- Use PowerShell cmdlets like `Get-ChildItem`, `New-Item`, etc.
- File paths should use Windows conventions (`\` separators)
- Use proper PowerShell escaping and quoting
- [ ] Use `;` instead of `&&` for command chaining
- [ ] Properly quote file paths for Windows
- [ ] Example: `cd "v:\path"; command` NOT `cd "v:\path" && command`
- [ ] Do not use `grep` in powershell commands
- [ ] Empty pipe elements are not allowed
- [ ] `lua -e "print('Testing...'); print('✅ Test passed!')"` is an example of an unnecessary command. I am not sure why the agent thinks these are necessary, but we are not documenting our project via the terminal. Do not use terminal commands to mark milestones.

## Project Structure
This is a Razor Pages project with:
- OpenIddict OIDC Server implementation
- Entity Framework Core with SQL Server (via Aspire)
- ASP.NET Core Identity
- Radzen components for Blazor applications

## Database Configuration

### Environment-Specific Database Strategy
The project uses intelligent database initialization:

- **Development**: Uses Entity Framework migrations for schema management
- **Production**: Uses Entity Framework migrations for reliable deployments  
- **Tests**: Uses `EnsureCreatedAsync()` for fast test database creation

### Test Database Configuration
When writing tests, the system automatically detects test environments and uses the appropriate database strategy:

```csharp
// Automatic test detection - no configuration needed
// Database will use EnsureCreatedAsync() in test environments

// Optional: Explicit test database configuration
services.AddSharedTestDatabase();     // Fast shared database for tests
services.AddIsolatedTestDatabase();   // Isolated database per test
```

### Development Database Workflow
1. Make entity changes
2. Create migration: `dotnet ef migrations add MigrationName`
3. Run application - migrations apply automatically
4. Commit migration files

### Test Database Best Practices
- Use shared test infrastructure when possible for speed
- Clean up test data if modifying shared database state
- Use isolated databases only when complete isolation is required
- Helper methods available: `RecreateTestDatabaseAsync()`, `ClearTestDatabaseDataAsync()`

## Code Style
- Use C# 13.0 syntax features
- Follow ASP.NET Core conventions
- Use dependency injection patterns
- Implement proper error handling
- Follow security best practices for OIDC/OAuth2
- Use mediator pattern for controllers
- Private instance fields start with underscore

## Development Workflow
- Use Visual Studio 2022 for development
- Commands should be executed in Visual Studio 2022 Developer PowerShell
- Build and run using `dotnet` CLI commands
- Database operations use Entity Framework migrations (development/production)
- Tests use EnsureCreatedAsync for fast database setup

## Blazor with Radzen - Critical Requirements

### CRITICAL: Radzen Components Setup
**ALWAYS** ensure `<RadzenComponents @rendermode="InteractiveServer" />` is present in MainLayout.razor for Radzen components to work properly:

```razor
@inherits LayoutComponentBase
<RadzenComponents @rendermode="InteractiveServer" />
<RadzenLayout>
  <!-- layout content -->
</RadzenLayout>
```

Without this component, Radzen UI components (dialogs, notifications, etc.) will not function correctly.

### CRITICAL: RadzenFormField Usage
**ALWAYS** wrap Radzen input controls in `RadzenFormField` unless there is a specific reason not to do so:

**✅ CORRECT - Controls wrapped in RadzenFormField:**
```razor
<RadzenFormField Text="Status" Variant="Variant.Outlined">
    <RadzenTextBox @bind-Value="@model.Status" Style="width: 100%;" />
</RadzenFormField>

<RadzenFormField Text="Name" Variant="Variant.Outlined">
    <RadzenTextBox @bind-Value="@model.Name" Style="width: 100%;" />
</RadzenFormField>
```

**Key Rules:**
1. RadzenFormField provides consistent styling and layout
2. Multiple controls can be placed in a single RadzenFormField when logically related
3. Use RadzenStack inside RadzenFormField only when you must organize multiple controls; avoid unnecessary wrappers
4. RadzenFormField handles proper spacing, borders, and visual hierarchy
5. Only exclude RadzenFormField when you need special layout handling

#### Standard pattern for boolean inputs (RadzenCheckBox and RadzenSwitch)
To maintain consistent spacing and alignment (40px row height, 7px vertical padding, 7px separation between control and text):

- Place the boolean control in the `Start` slot
- Place the text/label in `ChildContent` as a `RadzenLabel` linked via the `Component` attribute
- Do NOT add manual margins between the control and label; global CSS handles spacing
- Do NOT add extra top margins to align the control; global CSS aligns it
- Use this same pattern for both CheckBox and Switch

**✅ CORRECT - Checkbox with label:**
```razor
<RadzenFormField Text="Consent Requirements" Variant="Variant.Outlined">
    <Start>
        <RadzenCheckBox @bind-Value="@model.RequireConsent" TriState="true" Name="requireConsent" />
    </Start>
    <ChildContent>
        <RadzenLabel Text="Require user consent for authorization" Component="requireConsent" />
    </ChildContent>
    <Helper>
        <RadzenText TextStyle="TextStyle.Caption" class="rz-color-secondary">
            Controls when users must explicitly approve authorization
        </RadzenText>
    </Helper>
</RadzenFormField>
```

**✅ CORRECT - Switch with label:**
```razor
<RadzenFormField Text="Status" Variant="Variant.Outlined">
    <Start>
        <RadzenSwitch @bind-Value="@model.IsEnabled" OnLabel="Enabled" OffLabel="Disabled" />
    </Start>
    <ChildContent>
        <RadzenLabel Text="Client is enabled" />
    </ChildContent>
</RadzenFormField>
```

**❌ AVOID - Extra wrapper and manual spacing:**
```razor
<RadzenFormField Text="Consent Requirements" Variant="Variant.Outlined">
    <ChildContent>
        <RadzenStack Orientation="Orientation.Horizontal" AlignItems="AlignItems.Center" Gap="0.5rem" Style="margin-top: 0.5rem;">
            <RadzenCheckBox @bind-Value="@model.RequireConsent" Name="requireConsent" />
            <RadzenLabel Text="Require user consent for authorization" Component="requireConsent" />
        </RadzenStack>
    </ChildContent>
</RadzenFormField>
```

Notes:
- The global CSS adds: 40px min-height and 7px top/bottom padding to the content, 7px right padding to Start when it contains a checkbox/switch, and 7px top padding on the Start control. No inline spacing is needed.
- If `Start` is empty, no extra spacing is applied (selectors are conditional via `:has(...)`).

### CRITICAL: Async Methods in Event Handlers
When using async methods in Blazor event handlers, especially in lambda expressions, **ALWAYS** use `async` and `await`:

**❌ WRONG - Will not execute:**
```razor
<RadzenButton Click="@(() => DeleteRole(role))" />
```

**✅ CORRECT - Will execute properly:**
```razor
<RadzenButton Click="@(async () => await DeleteRole(role))" />
```

**Key Rules:**
1. Any async method call in a lambda must be awaited
2. The lambda must be marked as async
3. This applies to all event handlers: Click, Change, Submit, etc.
4. Failure to follow this pattern results in methods not being called at all

### Common Async Patterns in Blazor
```razor
<!-- Button clicks with async methods -->
<RadzenButton Click="@(async () => await SaveData())" />
<RadzenButton Click="@(async () => await DeleteItem(item.Id))" />

<!-- Form submissions -->
<RadzenTemplateForm Submit="@(async (args) => await OnSubmit(args))" />

<!-- Dropdown changes -->
<RadzenDropDown Change="@(async (value) => await OnSelectionChanged(value))" />

<!-- DataGrid actions -->
<Template Context="item">
    <RadzenButton Click="@(async () => await EditItem(item))" />
    <RadzenButton Click="@(async () => await DeleteItem(item))" />
</Template>
```

### Blazor Rendermode Requirements
- Use `@rendermode InteractiveServer` on pages with interactive components
- Ensure all Radzen components have proper rendermode inheritance
- Server-side rendering requires proper async handling

## Debugging Async Issues
If a method is not being called:
1. Check if the method is async and the lambda uses `async/await`
2. Verify `<RadzenComponents @rendermode="InteractiveServer" />` is in MainLayout
3. Check browser console for JavaScript errors
4. Verify proper rendermode is set on the page

## ⚠️ CRITICAL: OpenID Connect Discovery Endpoint URL Format

**ALWAYS use the correct OpenID Connect discovery endpoint URL format:**

✅ **CORRECT (Standard OIDC Spec):**
- `https://example.com/.well-known/openid-configuration`

❌ **INCORRECT (Common mistake):**
- `https://example.com/_well-known/openid_configuration`

This is the code block that represents the suggested code change:

### Key Points:
1. **The URL uses HYPHEN (-), not underscore (_)**
2. **This is defined by the OpenID Connect Discovery specification**
3. **Most OIDC clients automatically append this path to the Authority URL**
4. **Using underscore will cause discovery failures**

### When Configuring:
- **OpenIddict Server**: Use hyphen in endpoint configuration
- **Client Applications**: Authority URL should be base URL only (e.g., `https://localhost:7113`)
- **Manual Discovery**: Always test `/.well-known/openid-configuration` (with hyphen)

### Debugging Discovery Issues:
1. First check: Is the endpoint using hyphen or underscore?
2. Test manually: Browse to `{authority}/.well-known/openid-configuration`
3. Verify JSON response contains all required OIDC endpoints

## EF Core multi-provider migrations — authoritative checklist

Always create, validate, and commit provider-specific migrations for ALL supported providers whenever the domain model changes. Supported providers:
- SQL Server (project: MrWho.Migrations.SqlServer)
- PostgreSQL (project: MrWho.Migrations.PostgreSql)
- MySQL/MariaDB (project: MrWho.Migrations.MySql)

### 1) Generate migrations for each provider (from solution root)
Use the design-time factories already present in each migrations project. Run these commands (PowerShell) and replace `Name` with a descriptive change name:

- SQL Server:
  `dotnet ef migrations add Name_SqlServer -s "MrWho\MrWho.csproj" -p "MrWho.Migrations.SqlServer\MrWho.Migrations.SqlServer.csproj"; echo ""`

- PostgreSQL:
  `dotnet ef migrations add Name_PostgreSql -s "MrWho\MrWho.csproj" -p "MrWho.Migrations.PostgreSql\MrWho.Migrations.PostgreSql.csproj"; echo ""`

- MySQL/MariaDB:
  `dotnet ef migrations add Name_MySql -s "MrWho\MrWho.csproj" -p "MrWho.Migrations.MySql\MrWho.Migrations.MySql.csproj"; echo ""`

Notes:
- Run all three commands for every model change.
- Use the same base `Name` across providers to keep history aligned.

### 2) Ensure discoverability at runtime
- Each migration class should include:
  - `[DbContext(typeof(ApplicationDbContext))]`
  - `[Migration("<timestamp>_<Name>_Provider")]`
- If EF didn’t add attributes, add them manually.
- The MrWho.csproj already copies provider migrations DLLs next to the app on build/publish. Keep those targets intact.
- `AddMrWhoDatabase()` proactively loads the configured migrations assembly — do not remove this logic.

### 3) Provider-specific schema adjustments (must-verify)
- Strings/large text:
  - SQL Server: prefer explicit `HasMaxLength(...)` to avoid implicit `nvarchar(max)` when you want bounded columns.
  - PostgreSQL: if the model has `HasMaxLength(X)`, migrations must use `character varying(X)` (not `text`). Example: AuditLog.Changes -> `character varying(8000)`.
  - MySQL/MariaDB: large, variable-length strings should use `longtext` to avoid row size issues.
- Composite index key length (MySQL/MariaDB): add `.Annotation("MySql:IndexPrefixLength", new[] { ... })` for composite string indexes (e.g., `{ 256, 512, 0 }`).
- Date/time:
  - SQL Server: `datetime2`
  - PostgreSQL: `timestamp with time zone` where appropriate
  - MySQL/MariaDB: `datetime(6)`
- DataProtectionKeys table: ensure it’s included and matches the model (Id int identity, FriendlyName length 256, Xml text/longtext as needed per provider).
- OpenIddict entities: keep indexes and max lengths consistent with what OpenIddict EF stores expect.

### 4) Keep model and migrations in sync (no pending changes)
- If the model uses `HasMaxLength(...)`, reflect that in provider migrations (don’t fall back to `text`/`nvarchar(max)` unless intended).
- Verify the provider-specific `ApplicationDbContextModelSnapshot.cs` is updated alongside new migrations.
- Build the solution after generating all three provider migrations.
- Run the app with each provider setting (Database:Provider = SqlServer/PostgreSql/MySql) to ensure `MigrateAsync()` applies cleanly and no `PendingModelChangesWarning` appears.
- If EF logs pending changes, fix the mismatched provider migration immediately.

### 5) Local/dev/test specifics
- Tests use `EnsureCreatedAsync()` and may mask migration gaps. Always validate migrations by running the app against each real provider.
- In Docker, set `DOTNET_RUNNING_IN_CONTAINER=false` for app services that must use migrations (not EnsureCreated fallback).
- When a migration fails mid-way, bring the stack down with volumes (`down -v`) before retrying to avoid partial schema conflicts.

### 6) Production safety
- Do not rely on EnsureCreated in production. Always ship provider migrations with the app and let `Database.MigrateAsync()` run on startup.
- For MySQL/MariaDB, prefer `longtext` for very large strings and set index prefix lengths on composite indexes to prevent key length errors.

### 7) Naming & review checklist per change
- [ ] Created 3 migrations: SqlServer, PostgreSql, MySql with the same base name
- [ ] Attributes present: `[DbContext(...)]` and `[Migration("<timestamp>_Name_Provider")]`
- [ ] Index annotations for MySQL where composite string indexes exist
- [ ] Column types/lengths match model (`HasMaxLength`, `IsRequired`, etc.) for each provider
- [ ] Model snapshots updated for each provider project
- [ ] Built the solution and verified no pending changes warnings at runtime for each provider
- [ ] Committed all migration files

## Lessons learned: EF Core migrations across providers and Docker

- Keep provider migrations in sync:
    - Whenever the domain model changes, create and commit migrations for all supported providers: SqlServer, PostgreSql, MySql/MariaDb.
    - Do not rely on EnsureCreated for dev/prod; only for tests. Containers must run migrations.

- Make migrations discoverable at runtime:
    - In each provider-specific migration file, include attributes so EF picks them up: `[DbContext(typeof(ApplicationDbContext))]` and `[Migration("<timestamp>_<Name>")]` on the migration class. Prefer suffixing `<Name>` with the provider (e.g., `_SqlServer`, `_PostgreSql`, `_MySql`).
    - Ensure the app copies provider migrations assemblies into the published image and preload them before `Database.MigrateAsync()`.

- MySQL/MariaDB specifics:
    - Long composite indexes may exceed key length; use `MySql:IndexPrefixLength` annotations on affected indexes.
    - Large string columns can cause "Row size too large"; switch big varchars to `longtext` in MySQL/MariaDB migrations.
    - MariaDB healthcheck: prefer `CMD-SHELL` and `mariadb-admin ping -h 127.0.0.1 -uroot -p$MARIADB_ROOT_PASSWORD`.

- PostgreSQL specifics:
    - Respect `HasMaxLength(X)` with `character varying(X)` instead of `text` when the model specifies lengths (avoids pending changes).
    - Use `timestamp with time zone` where the model expects UTC timestamps and provider default aligns with that mapping.

- SQL Server specifics:
    - Prefer explicit `nvarchar(X)` for bounded columns when the model uses `HasMaxLength(X)`; avoid unintended `nvarchar(max)`.

- Container test detection pitfalls:
    - Env var `DOTNET_RUNNING_IN_CONTAINER` can trigger test heuristics; set `DOTNET_RUNNING_IN_CONTAINER=false` in compose for app services that must use migrations.

- Clean partial DB state when migrations fail:
    - If a migration fails mid-way, bring the stack down with volumes (`down -v`) before retrying to avoid duplicate column/table errors.