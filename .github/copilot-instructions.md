# GitHub Copilot Instructions for MrWho Project

## Terminal and Command Line Requirements

- **Always use PowerShell syntax** when executing commands in the terminal
- Use PowerShell cmdlets (e.g., `Get-ChildItem`, `Test-Path`, `New-Item`) instead of Unix/bash commands
- Use PowerShell operators and syntax patterns
- When suggesting terminal commands, default to PowerShell unless explicitly asked for another shell

## Examples of Preferred Commands

### File Operations
- Use `Get-ChildItem` instead of `ls`
- Use `New-Item` instead of `touch` or `mkdir`
- Use `Remove-Item` instead of `rm`
- Use `Copy-Item` instead of `cp`
- Use `Move-Item` instead of `mv`

### Directory Navigation
- Use `Set-Location` or `cd` (both work in PowerShell)
- Use `Get-Location` or `pwd` for current directory

### Environment Variables
- Use `$env:VARIABLE_NAME` syntax
- Use `[Environment]::SetEnvironmentVariable()` for setting variables

### .NET and Development Commands
- Use `dotnet` CLI commands as appropriate
- Prefer PowerShell for build scripts and automation

## Project Context
- This is a .NET 9 Aspire project with Blazor components
- The solution contains multiple projects including API services and web applications
- Prioritize .NET and Blazor-specific solutions and patterns
