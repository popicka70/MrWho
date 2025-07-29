# MrWho Database Management Script
# This script helps manage database operations for the MrWho project

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("migrate", "reset", "seed", "status", "help")]
    [string]$Action = "help",
    
    [Parameter(Mandatory=$false)]
    [string]$ConnectionString = "Data Source=(localdb)\MSSQLLocalDB;Initial Catalog=MrWhoDb;Integrated Security=True"
)

$ErrorActionPreference = "Stop"

function Write-Title {
    param([string]$Title)
    Write-Host ""
    Write-Host "=== $Title ===" -ForegroundColor Green
    Write-Host ""
}

function Write-Info {
    param([string]$Message)
    Write-Host "??  $Message" -ForegroundColor Cyan
}

function Write-Success {
    param([string]$Message)
    Write-Host "? $Message" -ForegroundColor Green
}

function Write-Warning {
    param([string]$Message)
    Write-Host "??  $Message" -ForegroundColor Yellow
}

function Write-Error {
    param([string]$Message)
    Write-Host "? $Message" -ForegroundColor Red
}

function Test-DatabaseConnection {
    param([string]$ConnectionString)
    
    try {
        $connection = New-Object System.Data.SqlClient.SqlConnection($ConnectionString)
        $connection.Open()
        $connection.Close()
        return $true
    }
    catch {
        return $false
    }
}

function Invoke-DatabaseMigration {
    Write-Title "Applying Database Migrations"
    
    try {
        Set-Location -Path "MrWho.ApiService"
        
        Write-Info "Checking for pending migrations..."
        $output = dotnet ef database update --connection $ConnectionString 2>&1
        
        if ($LASTEXITCODE -eq 0) {
            Write-Success "Database migrations applied successfully"
            Write-Host $output -ForegroundColor Gray
        } else {
            Write-Error "Failed to apply migrations"
            Write-Host $output -ForegroundColor Red
            throw "Migration failed"
        }
    }
    catch {
        Write-Error "Error during migration: $($_.Exception.Message)"
        throw
    }
    finally {
        Set-Location -Path ".."
    }
}

function Reset-Database {
    Write-Title "Resetting Database"
    
    $confirm = Read-Host "This will delete all data in the database. Are you sure? (y/N)"
    if ($confirm -ne "y" -and $confirm -ne "Y") {
        Write-Info "Database reset cancelled"
        return
    }
    
    try {
        Set-Location -Path "MrWho.ApiService"
        
        Write-Info "Dropping database..."
        dotnet ef database drop --connection $ConnectionString --force
        
        Write-Info "Applying migrations to recreate database..."
        dotnet ef database update --connection $ConnectionString
        
        Write-Success "Database reset completed"
    }
    catch {
        Write-Error "Error during database reset: $($_.Exception.Message)"
        throw
    }
    finally {
        Set-Location -Path ".."
    }
}

function Get-DatabaseStatus {
    Write-Title "Database Status"
    
    try {
        Write-Info "Testing database connection..."
        if (Test-DatabaseConnection -ConnectionString $ConnectionString) {
            Write-Success "Database connection successful"
        } else {
            Write-Error "Cannot connect to database"
            return
        }
        
        Set-Location -Path "MrWho.ApiService"
        
        Write-Info "Checking migration status..."
        $output = dotnet ef migrations list --connection $ConnectionString 2>&1
        
        if ($LASTEXITCODE -eq 0) {
            Write-Success "Migration status retrieved"
            Write-Host $output -ForegroundColor Gray
        } else {
            Write-Warning "Could not retrieve migration status"
            Write-Host $output -ForegroundColor Yellow
        }
        
        Write-Info "Checking database tables..."
        $query = @"
SELECT 
    TABLE_SCHEMA as [Schema],
    TABLE_NAME as [Table],
    TABLE_TYPE as [Type]
FROM INFORMATION_SCHEMA.TABLES 
WHERE TABLE_TYPE = 'BASE TABLE'
ORDER BY TABLE_SCHEMA, TABLE_NAME
"@
        
        try {
            $connection = New-Object System.Data.SqlClient.SqlConnection($ConnectionString)
            $connection.Open()
            $command = New-Object System.Data.SqlClient.SqlCommand($query, $connection)
            $reader = $command.ExecuteReader()
            
            Write-Info "Database tables:"
            while ($reader.Read()) {
                $schema = $reader["Schema"]
                $table = $reader["Table"]
                $type = $reader["Type"]
                Write-Host "  $schema.$table ($type)" -ForegroundColor Gray
            }
            
            $reader.Close()
            $connection.Close()
        }
        catch {
            Write-Warning "Could not retrieve table information: $($_.Exception.Message)"
        }
    }
    catch {
        Write-Error "Error checking database status: $($_.Exception.Message)"
    }
    finally {
        Set-Location -Path ".."
    }
}

function Start-Application {
    Write-Title "Starting Application for Database Seeding"
    
    Write-Info "Starting the Aspire application to trigger database seeding..."
    Write-Info "The application will automatically apply migrations and seed initial data."
    Write-Info "Press Ctrl+C to stop the application once seeding is complete."
    
    try {
        Set-Location -Path "MrWho.AppHost"
        dotnet run
    }
    catch {
        Write-Info "Application stopped"
    }
    finally {
        Set-Location -Path ".."
    }
}

function Show-Help {
    Write-Title "MrWho Database Management Script"
    
    Write-Host "Usage: .\Manage-Database.ps1 -Action <action> [-ConnectionString <connectionstring>]"
    Write-Host ""
    Write-Host "Actions:" -ForegroundColor Yellow
    Write-Host "  migrate    - Apply pending database migrations"
    Write-Host "  reset      - Drop and recreate the database (WARNING: Deletes all data)"
    Write-Host "  seed       - Start the application to trigger automatic seeding"
    Write-Host "  status     - Show database connection and migration status"
    Write-Host "  help       - Show this help message"
    Write-Host ""
    Write-Host "Examples:" -ForegroundColor Yellow
    Write-Host "  .\Manage-Database.ps1 -Action migrate"
    Write-Host "  .\Manage-Database.ps1 -Action status"
    Write-Host "  .\Manage-Database.ps1 -Action reset"
    Write-Host "  .\Manage-Database.ps1 -Action seed"
    Write-Host ""
    Write-Host "Connection String:" -ForegroundColor Yellow
    Write-Host "  Default: Data Source=(localdb)\MSSQLLocalDB;Initial Catalog=MrWhoDb;Integrated Security=True"
    Write-Host "  Override with -ConnectionString parameter"
    Write-Host ""
}

# Main execution
try {
    switch ($Action.ToLower()) {
        "migrate" { Invoke-DatabaseMigration }
        "reset" { Reset-Database }
        "seed" { Start-Application }
        "status" { Get-DatabaseStatus }
        "help" { Show-Help }
        default { 
            Write-Error "Unknown action: $Action"
            Show-Help
            exit 1
        }
    }
}
catch {
    Write-Error "Script execution failed: $($_.Exception.Message)"
    exit 1
}