# Internal Link Validator for MrWho Documentation
# Checks all markdown links that are relative paths (not URLs)

$ErrorActionPreference = 'Continue'
$root = "c:\Users\rum2c\source\repos\MrWhoOidc\MrWho"
$broken = @()
$checked = @()

# Find all markdown files
$mdFiles = Get-ChildItem -Path $root -Recurse -Filter "*.md" -File

Write-Host "Checking internal links in $($mdFiles.Count) markdown files..." -ForegroundColor Cyan
Write-Host ""

foreach ($file in $mdFiles) {
    $relativePath = $file.FullName.Replace("$root\", "")
    $content = Get-Content $file.FullName -Raw
    
    # Extract markdown links [text](path) - exclude URLs
    $links = [regex]::Matches($content, '\[([^\]]+)\]\(([^h][^)]+)\)')
    
    if ($links.Count -eq 0) { continue }
    
    Write-Host "Checking $relativePath ($($links.Count) links):" -ForegroundColor Yellow
    
    foreach ($match in $links) {
        $linkText = $match.Groups[1].Value
        $linkPath = $match.Groups[2].Value
        
        # Remove anchor fragments
        $linkPathNoAnchor = $linkPath -replace '#.*$', ''
        
        # Skip empty paths (anchor-only links)
        if ([string]::IsNullOrWhiteSpace($linkPathNoAnchor)) { continue }
        
        # Resolve relative path from the file's directory
        $fileDir = Split-Path $file.FullName -Parent
        $targetPath = Join-Path $fileDir $linkPathNoAnchor
        $targetPath = [System.IO.Path]::GetFullPath($targetPath)
        
        # Check if target exists
        $exists = Test-Path $targetPath
        
        $checkKey = "$relativePath -> $linkPath"
        if ($checked -contains $checkKey) { continue }
        $checked += $checkKey
        
        if ($exists) {
            Write-Host "  ✓ $linkPath" -ForegroundColor Green
        } else {
            Write-Host "  ✗ $linkPath (target not found)" -ForegroundColor Red
            $broken += [PSCustomObject]@{
                SourceFile = $relativePath
                LinkText = $linkText
                LinkPath = $linkPath
                ResolvedPath = $targetPath
            }
        }
    }
    
    Write-Host ""
}

# Summary
Write-Host "================================" -ForegroundColor Cyan
Write-Host "SUMMARY" -ForegroundColor Cyan
Write-Host "================================" -ForegroundColor Cyan
Write-Host "Total links checked: $($checked.Count)" -ForegroundColor White
Write-Host "Broken links: $($broken.Count)" -ForegroundColor $(if ($broken.Count -eq 0) { "Green" } else { "Red" })

if ($broken.Count -gt 0) {
    Write-Host ""
    Write-Host "BROKEN LINKS:" -ForegroundColor Red
    Write-Host "================================" -ForegroundColor Red
    foreach ($b in $broken) {
        Write-Host "File: $($b.SourceFile)" -ForegroundColor Yellow
        Write-Host "  Link: [$($b.LinkText)]($($b.LinkPath))" -ForegroundColor White
        Write-Host "  Expected: $($b.ResolvedPath)" -ForegroundColor Gray
        Write-Host ""
    }
    exit 1
} else {
    Write-Host ""
    Write-Host "All internal links are valid! ✓" -ForegroundColor Green
    exit 0
}
