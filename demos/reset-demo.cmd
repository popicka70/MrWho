@echo off
setlocal

REM MrWho demo reset helper (CMD wrapper)
REM Usage:
REM   reset-demo.cmd
REM   reset-demo.cmd -RemoveImages
REM   reset-demo.cmd -PruneDanglingImages

set "SCRIPT_DIR=%~dp0"
set "PS1=%SCRIPT_DIR%reset-demo.ps1"

if not exist "%PS1%" (
  echo Reset script not found: %PS1%
  exit /b 1
)

REM Prefer PowerShell 7+ (pwsh) if available, otherwise fall back to Windows PowerShell.
where pwsh >nul 2>nul
if %ERRORLEVEL% EQU 0 (
  pwsh -NoProfile -ExecutionPolicy Bypass -File "%PS1%" %*
  exit /b %ERRORLEVEL%
)

where powershell >nul 2>nul
if %ERRORLEVEL% EQU 0 (
  powershell -NoProfile -ExecutionPolicy Bypass -File "%PS1%" %*
  exit /b %ERRORLEVEL%
)

echo Neither 'pwsh' nor 'powershell' was found on PATH.
echo Install PowerShell or run the script manually.
exit /b 1
