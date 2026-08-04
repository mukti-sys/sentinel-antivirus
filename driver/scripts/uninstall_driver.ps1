# uninstall_driver.ps1 — Unload and remove SentinelFilter.
#
# Run as Administrator inside the VM.

#Requires -RunAsAdministrator

$ErrorActionPreference = "SilentlyContinue"

Write-Host "=== Sentinel Filter — Uninstall ===" -ForegroundColor Cyan

# Step 1: Unload the minifilter.
Write-Host "`n[1/3] Unloading minifilter..." -ForegroundColor Yellow
fltmc unload SentinelFilter
if ($LASTEXITCODE -eq 0) {
    Write-Host "  Minifilter unloaded."
} else {
    Write-Host "  Minifilter was not loaded (or already unloaded)."
}

# Step 2: Delete the service.
Write-Host "`n[2/3] Deleting service..." -ForegroundColor Yellow
sc.exe delete SentinelFilter
if ($LASTEXITCODE -eq 0) {
    Write-Host "  Service deleted."
} else {
    Write-Host "  Service did not exist (or already deleted)."
}

# Step 3: Remove the driver binary.
Write-Host "`n[3/3] Removing driver binary..." -ForegroundColor Yellow
$sysPath = "$env:SystemRoot\System32\drivers\SentinelFilter.sys"
if (Test-Path $sysPath) {
    Remove-Item $sysPath -Force
    Write-Host "  Removed: $sysPath"
} else {
    Write-Host "  Driver binary was not present."
}

Write-Host "`n=== SentinelFilter removed ===" -ForegroundColor Green
