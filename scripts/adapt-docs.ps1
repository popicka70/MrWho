# Documentation Adaptation Script for Public Repository
# Adapts documentation from main solution to public repo structure

$ErrorActionPreference = "Stop"

Write-Host "Adapting documentation for public repository..." -ForegroundColor Cyan

# Documentation files to adapt
$docFiles = @(
    "deployment-guide.md",
    "upgrade-guide.md", 
    "docker-compose-examples.md",
    "docker-security-best-practices.md",
    "admin-guide.md",
    "multitenancy-quick-reference.md",
    "key-rotation-playbook.md"
)

$adaptCount = 0
$docsDir = "docs"

foreach ($file in $docFiles) {
    $filePath = Join-Path $docsDir $file
    
    if (-not (Test-Path $filePath)) {
        Write-Host "  ⚠ Skipping $file (not found)" -ForegroundColor Yellow
        continue
    }
    
    Write-Host "  Adapting $file..." -ForegroundColor Gray
    
    # Read file content
    $content = Get-Content $filePath -Raw
    
    # Track if changes were made
    $changed = $false
    
    # 1. Remove Aspire AppHost references
    if ($content -match "Aspire|AppHost|\.AppHost") {
        $content = $content -replace "Aspire\.Hosting\.", ""
        $content = $content -replace "MrWhoOidc\.AppHost", "docker-compose"
        $content = $content -replace "\.AppHost", ""
        $content = $content -replace "Aspire dashboard", "monitoring dashboard"
        $changed = $true
    }
    
    # 2. Update build instructions to use GHCR images
    if ($content -match "docker build|dotnet build|Building from source") {
        $content = $content -replace "docker build.*", "docker pull ghcr.io/popicka70/mrwhooidc:latest"
        $content = $content -replace "Build the Docker image.*", "Pull the Docker image from GitHub Container Registry"
        $content = $content -replace "Building from source is.*", "Use pre-built Docker images from GHCR for deployment"
        $changed = $true
    }
    
    # 3. Update image references from local builds to GHCR
    if ($content -match "image:\s*mrwhooidc" -or $content -match "image:\s*ghcr\.io/popicka70/mrwhooidc") {
        $content = $content -replace "image:\s*mrwhooidc:latest", "image: ghcr.io/popicka70/mrwhooidc:latest"
        $content = $content -replace "image:\s*mrwhooidc:.*", "image: ghcr.io/popicka70/mrwhooidc:`$VERSION"
        $changed = $true
    }
    
    # 4. Update file paths from main solution to public repo
    $content = $content -replace "MrWhoOidc\.WebAuth/", ""
    $content = $content -replace "MrWhoOidc\.Auth/", ""
    $content = $content -replace "/src/", "/"
    $content = $content -replace "Examples/", "demos/"
    
    # 5. Add explicit version numbers
    if ($content -match "latest|current version") {
        # Add note about versioning
        $versionNote = "`n> **Note**: This documentation is for MrWhoOidc v1.0.0 and later. Check the GitHub releases page for the latest version.`n"
        if ($content -notmatch "This documentation is for MrWhoOidc") {
            $content = $content -replace "(#\s+[^\n]+\n)", "`$1$versionNote"
            $changed = $true
        }
    }
    
    # 6. Update internal documentation links
    $content = $content -replace "\[([^\]]+)\]\(\.\./docs/", "[`$1](docs/"
    $content = $content -replace "\[([^\]]+)\]\(docs/docs/", "[`$1](docs/"
    
    # 7. Remove references to non-public documentation
    $privateDocsPattern = "phase\d+|backlog|implementation-summary|progress|audit|fix|complete"
    $content = $content -replace "\[([^\]]+)\]\([^\)]*($privateDocsPattern)[^\)]*\)", "`$1 (internal documentation)"
    
    # 8. Update repository URLs
    $content = $content -replace "https://github\.com/[^/]+/MrWhoOidc", "https://github.com/popicka70/mrwhooidc"
    
    # Write adapted content back
    Set-Content $filePath $content -NoNewline
    $adaptCount++
    Write-Host "    ✓ Adapted $file" -ForegroundColor Green
}

Write-Host "`n✓ Adapted $adaptCount documentation files" -ForegroundColor Green
Write-Host "  Location: $docsDir/" -ForegroundColor Gray
