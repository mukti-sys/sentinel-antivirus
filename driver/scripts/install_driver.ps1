# install_driver.ps1 — Sign, install, and load SentinelFilter.
#
# Run as Administrator inside the VM.
# ALWAYS take a VM snapshot before running this.

#Requires -RunAsAdministrator

$ErrorActionPreference = "Stop"

$DriverDir = "$PSScriptRoot\..\SentinelFilter"
$SysFile   = "$DriverDir\x64\Debug\SentinelFilter.sys"
$InfFile   = "$DriverDir\SentinelFilter.inf"
$PfxFile   = "$DriverDir\SentinelFilter.pfx"
$PfxPass   = "SentinelTest2026!"

Write-Host "=== Sentinel Filter — Install ===" -ForegroundColor Cyan

# Step 0: Preflight checks.
if (-not (Test-Path $SysFile)) {
    Write-Host "[ERROR] Driver binary not found: $SysFile" -ForegroundColor Red
    Write-Host "  Build the driver first:"
    Write-Host "  msbuild SentinelFilter.vcxproj /p:Configuration=Debug /p:Platform=x64"
    exit 1
}

if (-not (Test-Path $PfxFile)) {
    Write-Host "[ERROR] Certificate PFX not found: $PfxFile" -ForegroundColor Red
    Write-Host "  Run setup_signing.ps1 first."
    exit 1
}

# Step 1: Sign the driver binary.
Write-Host "`n[1/3] Signing $SysFile" -ForegroundColor Yellow
signtool sign /fd SHA256 /f "$PfxFile" /p "$PfxPass" /v "$SysFile"
if ($LASTEXITCODE -ne 0) {
    Write-Host "[ERROR] signtool failed." -ForegroundColor Red
    exit 1
}
Write-Host "  Driver signed successfully."

# Step 2: Install via INF (creates Instances registry subkey).
Write-Host "`n[2/3] Installing via INF: $InfFile" -ForegroundColor Yellow
# Copy .sys to System32\drivers first (INF CopyFiles needs it available).
Copy-Item $SysFile "$env:SystemRoot\System32\drivers\SentinelFilter.sys" -Force
# Install INF (creates service + Instances registry entries).
rundll32.exe setupapi.dll,InstallHinfSection DefaultInstall 132 "$InfFile"
Write-Host "  INF installed. Checking registry..."

# Verify registry key was created.
$regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\SentinelFilter\Instances"
if (Test-Path $regPath) {
    Write-Host "  Instances registry key: OK" -ForegroundColor Green
} else {
    Write-Host "  [WARNING] Instances key not found at $regPath" -ForegroundColor Yellow
    Write-Host "  fltmc load may fail."
}

# Step 3: Load the minifilter.
Write-Host "`n[3/3] Loading minifilter..." -ForegroundColor Yellow
fltmc load SentinelFilter
if ($LASTEXITCODE -ne 0) {
    Write-Host "[ERROR] fltmc load failed. Check:" -ForegroundColor Red
    Write-Host "  1. Test signing enabled (bcdedit /enum | findstr testsigning)"
    Write-Host "  2. Driver is properly signed (signtool verify /pa SentinelFilter.sys)"
    Write-Host "  3. Instances registry key exists"
    exit 1
}

Write-Host "`n=== SentinelFilter loaded ===" -ForegroundColor Green
Write-Host "`nCurrently loaded minifilters:"
fltmc
