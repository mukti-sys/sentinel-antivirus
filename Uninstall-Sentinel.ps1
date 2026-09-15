# ==============================================================================
#                     SENTINEL ANTIVIRUS UNINSTALLER
# ==============================================================================

[CmdletBinding()]
param(
    [string]$InstallDir = "$env:ProgramFiles\Sentinel Antivirus",
    [switch]$KeepLogs
)

$ErrorActionPreference = "Continue"

function Assert-Administrator {
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Host "[*] Elevating to Administrator..." -ForegroundColor Yellow
        $argsList = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
        Start-Process powershell.exe -Verb RunAs -ArgumentList $argsList
        exit
    }
}

Assert-Administrator

Write-Host "==================================================================" -ForegroundColor Yellow
Write-Host "             SENTINEL ANTIVIRUS UNINSTALLATION                    " -ForegroundColor Yellow
Write-Host "==================================================================" -ForegroundColor Yellow

# 1. Terminate running applications
Write-Host "[1/5] Terminating active Sentinel processes..." -ForegroundColor Cyan
Get-Process sentinel_tray, sentinel_gui -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue

# 2. Stop and unregister Windows Service
Write-Host "[2/5] Removing Windows Service (SentinelService)..." -ForegroundColor Cyan
if (Get-Service -Name "SentinelService" -ErrorAction SilentlyContinue) {
    Stop-Service -Name "SentinelService" -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 1
    sc.exe delete SentinelService | Out-Null
    Write-Host "      SentinelService stopped and removed from SCM." -ForegroundColor Green
}

# 3. Clean up Canary traps
Write-Host "[3/5] Disarming ransomware canaries..." -ForegroundColor Cyan
$CliExe = Join-Path $InstallDir "sentinel_cli.exe"
if (Test-Path $CliExe) {
    & $CliExe canaries --disarm | Out-Null
}

# 4. Remove Registry keys & shortcuts
Write-Host "[4/5] Removing startup entries and shortcuts..." -ForegroundColor Cyan
Remove-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "SentinelAntivirusTray" -ErrorAction SilentlyContinue

# Start Menu
$StartMenuDir = "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Sentinel Antivirus"
if (Test-Path $StartMenuDir) { Remove-Item -Path $StartMenuDir -Recurse -Force -ErrorAction SilentlyContinue }

# Desktop
$DesktopPath = [System.Environment]::GetFolderPath([System.Environment+SpecialFolder]::CommonDesktopDirectory)
$DeskShortcut = Join-Path $DesktopPath "Sentinel Antivirus.lnk"
if (Test-Path $DeskShortcut) { Remove-Item -Path $DeskShortcut -Force -ErrorAction SilentlyContinue }

# 5. Clean up files
Write-Host "[5/5] Removing application files from: $InstallDir" -ForegroundColor Cyan
if (Test-Path $InstallDir) {
    if (-not $KeepLogs) {
        Remove-Item -Path $InstallDir -Recurse -Force -ErrorAction SilentlyContinue
    } else {
        Get-ChildItem -Path $InstallDir -Exclude "data", "logs" | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Write-Host "==================================================================" -ForegroundColor Green
Write-Host "         SENTINEL ANTIVIRUS SUCCESSFULLY UNINSTALLED              " -ForegroundColor Green
Write-Host "==================================================================" -ForegroundColor Green
