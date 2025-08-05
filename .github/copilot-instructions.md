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
1. **Any async method call in a lambda must be awaited**
2. **The lambda must be marked as async**
3. **This applies to all event handlers: Click, Change, Submit, etc.**
4. **Failure to follow this pattern results in methods not being called at all**

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