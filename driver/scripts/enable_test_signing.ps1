# enable_test_signing.ps1 — Enable Windows test-signing mode.
#
# Run as Administrator inside the VM.
# REQUIRES A REBOOT to take effect.
# REQUIRES Secure Boot to be DISABLED in VM BIOS.

#Requires -RunAsAdministrator

$ErrorActionPreference = "Stop"

Write-Host "=== Sentinel Filter — Enable Test Signing ===" -ForegroundColor Cyan

# Check if already enabled.
$bcdOutput = bcdedit /enum | Select-String "testsigning\s+Yes"
if ($bcdOutput) {
    Write-Host "`nTest signing is ALREADY ENABLED." -ForegroundColor Green
    Write-Host "No reboot needed."
    exit 0
}

Write-Host "`n[WARNING] This enables test-signing mode." -ForegroundColor Yellow
Write-Host "  - A 'Test Mode' watermark will appear on the desktop."
Write-Host "  - Secure Boot must be DISABLED in VM BIOS."
Write-Host "  - This should ONLY be done inside a VM, NEVER on your host."
Write-Host ""

# Enable test signing.
Write-Host "Running: bcdedit /set testsigning on" -ForegroundColor Yellow
bcdedit /set testsigning on

if ($LASTEXITCODE -ne 0) {
    Write-Host "`n[ERROR] bcdedit failed. Possible causes:" -ForegroundColor Red
    Write-Host "  1. Not running as Administrator"
    Write-Host "  2. Secure Boot is enabled (disable in VM BIOS)"
    exit 1
}

Write-Host "`n=== Test signing enabled ===" -ForegroundColor Green
Write-Host "REBOOT the VM for changes to take effect."
Write-Host ""

$restart = Read-Host "Restart now? (y/N)"
if ($restart -eq "y" -or $restart -eq "Y") {
    Restart-Computer -Force
}
