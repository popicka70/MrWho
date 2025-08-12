# Device Management Database Setup Script
# This script helps resolve SQL Server cascade constraint issues with the new device management tables

Write-Host "?? MrWho Device Management - Database Setup Helper" -ForegroundColor Green
Write-Host "=================================================" -ForegroundColor Green
Write-Host ""

$MrWhoPath = "C:\Users\rum2c\source\repos\MrWho\MrWho"

Write-Host "?? Checking current directory..." -ForegroundColor Yellow
if (Test-Path $MrWhoPath) {
    Set-Location $MrWhoPath
    Write-Host "? Located MrWho project directory" -ForegroundColor Green
} else {
    Write-Host "? Could not find MrWho project directory" -ForegroundColor Red
    Write-Host "Please update the path in this script or run from the correct directory" -ForegroundColor Yellow
    exit 1
}

Write-Host ""
Write-Host "??? Database Setup Options:" -ForegroundColor Cyan
Write-Host "1. Drop and recreate database (recommended for SQL Server cascade issues)" -ForegroundColor White
Write-Host "2. Just apply migrations (if cascade issues are resolved)" -ForegroundColor White
Write-Host "3. Check database status" -ForegroundColor White
Write-Host "4. Start Aspire AppHost" -ForegroundColor White
Write-Host ""

$choice = Read-Host "Select option (1-4)"

switch ($choice) {
    "1" {
        Write-Host ""
        Write-Host "?? Dropping and recreating database..." -ForegroundColor Yellow
        Write-Host "This will resolve SQL Server cascade constraint issues with device management tables" -ForegroundColor Yellow
        Write-Host ""
        
        try {
            # Drop database
            Write-Host "?? Dropping existing database..." -ForegroundColor Yellow
            dotnet ef database drop --force
            
            # Recreate with migrations
            Write-Host "?? Creating database with all migrations..." -ForegroundColor Yellow
            dotnet ef database update
            
            Write-Host ""
            Write-Host "? Database successfully recreated!" -ForegroundColor Green
            Write-Host "?? Device management tables are now ready" -ForegroundColor Green
        }
        catch {
            Write-Host ""
            Write-Host "? Error during database recreation: $($_.Exception.Message)" -ForegroundColor Red
            Write-Host "?? Try option 4 to start Aspire - it will use EnsureCreated fallback" -ForegroundColor Yellow
        }
    }
    
    "2" {
        Write-Host ""
        Write-Host "?? Applying migrations..." -ForegroundColor Yellow
        
        try {
            dotnet ef database update
            Write-Host "? Migrations applied successfully!" -ForegroundColor Green
        }
        catch {
            Write-Host "? Migration failed: $($_.Exception.Message)" -ForegroundColor Red
            Write-Host "?? Try option 1 to drop and recreate the database" -ForegroundColor Yellow
        }
    }
    
    "3" {
        Write-Host ""
        Write-Host "?? Checking database status..." -ForegroundColor Yellow
        
        try {
            # List pending migrations
            $pendingMigrations = dotnet ef migrations list --json | ConvertFrom-Json | Where-Object { $_.Applied -eq $false }
            $appliedMigrations = dotnet ef migrations list --json | ConvertFrom-Json | Where-Object { $_.Applied -eq $true }
            
            Write-Host ""
            Write-Host "? Applied Migrations: $($appliedMigrations.Count)" -ForegroundColor Green
            Write-Host "? Pending Migrations: $($pendingMigrations.Count)" -ForegroundColor Yellow
            
            if ($pendingMigrations.Count -gt 0) {
                Write-Host ""
                Write-Host "Pending migrations:" -ForegroundColor Yellow
                foreach ($migration in $pendingMigrations) {
                    Write-Host "  - $($migration.Name)" -ForegroundColor White
                }
            }
            
            Write-Host ""
            Write-Host "?? You can also check status at: https://localhost:7113/debug/device-management-status" -ForegroundColor Cyan
        }
        catch {
            Write-Host "? Error checking database status: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
    
    "4" {
        Write-Host ""
        Write-Host "?? Starting Aspire AppHost..." -ForegroundColor Green
        Write-Host "This will automatically handle database setup with EnsureCreated fallback" -ForegroundColor Yellow
        Write-Host ""
        
        Set-Location "../MrWhoAdmin.AppHost"
        dotnet run
    }
    
    default {
        Write-Host "? Invalid option selected" -ForegroundColor Red
    }
}

Write-Host ""
Write-Host "?? Device Management Features Available:" -ForegroundColor Cyan
Write-Host "  • Device Registration: /device-management/register" -ForegroundColor White
Write-Host "  • Device Dashboard: /device-management" -ForegroundColor White
Write-Host "  • Enhanced QR Login: /qr-login/start?persistent=true" -ForegroundColor White
Write-Host "  • Device API: /api/devices" -ForegroundColor White
Write-Host "  • Debug Status: /debug/device-management-status" -ForegroundColor White
Write-Host ""
Write-Host "?? The device management system is ready to use!" -ForegroundColor Green