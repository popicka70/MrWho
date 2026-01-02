[CmdletBinding()]
param(
    # Compose project name used for "docker compose down".
    # This does NOT need to match a previous run; containers are removed by name first.
    [string] $ProjectName = "mrwho-demo",

    # Also remove locally-built images used by the demo (safe/targeted).
    [switch] $RemoveImages,

    # Also prune dangling images (more aggressive; can remove unrelated dangling layers).
    [switch] $PruneDanglingImages
)

$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$composeFile = Join-Path $scriptDir "docker-compose.yml"

if (-not (Test-Path $composeFile)) {
    throw "Compose file not found: $composeFile"
}

Write-Host "Resetting MrWho demo Docker environment..." -ForegroundColor Cyan
Write-Host "- Compose file: $composeFile"
Write-Host "- Project name: $ProjectName"

# Containers use explicit container_name in docker-compose.yml.
# Removing by name avoids conflicts when a previous run used a different COMPOSE_PROJECT_NAME.
$containerNames = @(
    "mrwho-oidc-demo",
    "mrwho-postgres-demo",
    "dotnet-mvc-demo",
    "react-spa-demo",
    "go-client-demo"
)

foreach ($name in $containerNames) {
    try {
        & docker rm -f $name 2>$null | Out-Null
        Write-Host "Removed container: $name" -ForegroundColor DarkGray
    } catch {
        # Ignore missing containers / non-zero exit codes
    }
}

# Bring the compose project down (removes networks created by this compose project too)
try {
    & docker compose -f $composeFile -p $ProjectName down --volumes --remove-orphans
} catch {
    # Ignore errors here; container removals above handle most issues
}

# Remove any leftover demo postgres volumes.
# Note: without an explicit 'name:' in compose, Docker Compose prefixes volumes with the project name.
# This targets volumes ending in '_demo-postgres-data' (or exactly 'demo-postgres-data' if you add name:).
try {
    $volumes = & docker volume ls --format "{{.Name}}"
    $demoVolumes = $volumes | Where-Object { $_ -match '(^demo-postgres-data$|_demo-postgres-data$)' }

    foreach ($vol in $demoVolumes) {
        try {
            & docker volume rm $vol 2>$null | Out-Null
            Write-Host "Removed volume: $vol" -ForegroundColor DarkGray
        } catch {
            # ignore
        }
    }
} catch {
    # ignore
}

if ($RemoveImages) {
    # Only the OIDC image is explicitly tagged in the compose.
    $images = @(
        "mrwhooidc:local"
    )

    foreach ($img in $images) {
        try {
            & docker image rm -f $img 2>$null | Out-Null
            Write-Host "Removed image: $img" -ForegroundColor DarkGray
        } catch {
            # ignore
        }
    }
}

if ($PruneDanglingImages) {
    try {
        & docker image prune -f | Out-Null
        Write-Host "Pruned dangling images." -ForegroundColor DarkGray
    } catch {
        # ignore
    }
}

Write-Host "Demo reset complete." -ForegroundColor Green
