# Copy ioc_submission project to a local folder for faster editing,
# then optionally sync back to the network share.
# Run from project root or pass -SourcePath.
#
# Usage:
#   .\scripts\copy-to-local.ps1
#   .\scripts\copy-to-local.ps1 -Destination "C:\dev\ioc_submission"
#   .\scripts\copy-to-local.ps1 -SourcePath "\\10.11.209.188\ioc_submission" -Destination "C:\dev\ioc_submission"

param(
    [string]$SourcePath = $PSScriptRoot + "\..",
    [string]$Destination = "C:\dev\ioc_submission"
)

$SourcePath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($SourcePath)
if (-not (Test-Path $SourcePath)) {
    Write-Error "Source not found: $SourcePath"
    exit 1
}

if (-not (Test-Path $Destination)) {
    New-Item -ItemType Directory -Path $Destination -Force | Out-Null
    Write-Host "Created: $Destination"
}

# Exclude common non-essential folders to speed up copy
$exclude = @('__pycache__', '.git', 'node_modules', '.venv', 'venv')
$childDirs = Get-ChildItem -Path $SourcePath -Directory -ErrorAction SilentlyContinue | Where-Object { $exclude -notcontains $_.Name }
$childFiles = Get-ChildItem -Path $SourcePath -File -ErrorAction SilentlyContinue

foreach ($item in $childFiles) {
    Copy-Item -Path $item.FullName -Destination (Join-Path $Destination $item.Name) -Force
    Write-Host "  Copied: $($item.Name)"
}
foreach ($dir in $childDirs) {
    $destSub = Join-Path $Destination $dir.Name
    if (-not (Test-Path $destSub)) { New-Item -ItemType Directory -Path $destSub -Force | Out-Null }
    Copy-Item -Path ($dir.FullName + "\*") -Destination $destSub -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "  Copied dir: $($dir.Name)"
}

Write-Host "Done. Local copy at: $Destination"
Write-Host "Edit files there, then sync back to the network share when ready."
