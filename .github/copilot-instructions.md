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
- Entity Framework Core with SQLite
- ASP.NET Core Identity
- Bootstrap 5 for UI styling

## Code Style
- Use C# 13.0 syntax features
- Follow ASP.NET Core conventions
- Use dependency injection patterns
- Implement proper error handling
- Follow security best practices for OIDC/OAuth2

## Development Workflow
- Use Visual Studio 2022 for development
- Commands should be executed in Visual Studio 2022 Developer PowerShell
- Build and run using `dotnet` CLI commands
- Database operations use Entity Framework migrations