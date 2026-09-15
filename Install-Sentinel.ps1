# ==============================================================================
#                      SENTINEL ANTIVIRUS INSTALLER
# ==============================================================================
# Deploys Sentinel Antivirus to Program Files, creates the NT SYSTEM service,
# configures automatic boot recovery, and arms the system tray companion.
# ==============================================================================

[CmdletBinding()]
param(
    [string]$InstallDir = "$env:ProgramFiles\Sentinel Antivirus",
    [switch]$NoDesktopShortcut,
    [switch]$NoStartService
)

$ErrorActionPreference = "Stop"

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

Write-Host "==================================================================" -ForegroundColor Cyan
Write-Host "               SENTINEL ANTIVIRUS INSTALLATION                    " -ForegroundColor Cyan
Write-Host "==================================================================" -ForegroundColor Cyan

$SourceDir = $PSScriptRoot

# 1. Stop running processes
Write-Host "[1/6] Stopping existing Sentinel instances..." -ForegroundColor Cyan
Get-Process sentinel_tray, sentinel_gui -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
if (Get-Service -Name "SentinelService" -ErrorAction SilentlyContinue) {
    Write-Host "      Stopping existing SentinelService..." -ForegroundColor Gray
    Stop-Service -Name "SentinelService" -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
}

# 2. Copy files to Program Files
Write-Host "[2/6] Deploying files to: $InstallDir" -ForegroundColor Cyan
if (-not (Test-Path $InstallDir)) {
    New-Item -Path $InstallDir -ItemType Directory -Force | Out-Null
}

Copy-Item -Path "$SourceDir\*" -Destination $InstallDir -Recurse -Force
Write-Host "      Files successfully copied." -ForegroundColor Green

# 3. Create Windows Service
Write-Host "[3/6] Configuring Windows Service (SentinelService)..." -ForegroundColor Cyan
$ServiceExe = Join-Path $InstallDir "sentinel_service.exe"

if (-not (Test-Path $ServiceExe)) {
    Write-Error "Could not find sentinel_service.exe in $InstallDir"
}

if (-not (Get-Service -Name "SentinelService" -ErrorAction SilentlyContinue)) {
    New-Service -Name "SentinelService" `
                -BinaryPathName "`"$ServiceExe`"" `
                -DisplayName "Sentinel Antivirus Core Protection Service" `
                -Description "Real-time kernel minifilter, 5M PE machine learning classifier, and ransomware canary defense." `
                -StartupType Automatic | Out-Null
    Write-Host "      Registered SentinelService with SCM." -ForegroundColor Green
} else {
    sc.exe config SentinelService binPath= "`"$ServiceExe`"" start= auto | Out-Null
    Write-Host "      Updated SentinelService configuration." -ForegroundColor Green
}

# SCM Recovery: Restart after 5s, 10s, 30s; reset fail counter after 24h
sc.exe failure SentinelService reset= 86400 actions= restart/5000/restart/10000/restart/30000 | Out-Null

# 4. Configure Auto-Start System Tray Companion
Write-Host "[4/6] Registering System Tray Companion in Windows Startup..." -ForegroundColor Cyan
$TrayExe = Join-Path $InstallDir "sentinel_tray.exe"
$RunKey = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
Set-ItemProperty -Path $RunKey -Name "SentinelAntivirusTray" -Value "`"$TrayExe`"" -Force
Write-Host "      System Tray auto-start configured." -ForegroundColor Green

# 5. Create Start Menu & Desktop Shortcuts
Write-Host "[5/6] Creating application shortcuts..." -ForegroundColor Cyan
$WshShell = New-Object -ComObject WScript.Shell
$GuiExe = Join-Path $InstallDir "sentinel_gui.exe"

# Start Menu
$StartMenuDir = "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Sentinel Antivirus"
if (-not (Test-Path $StartMenuDir)) { New-Item -Path $StartMenuDir -ItemType Directory -Force | Out-Null }
$StartShortcut = $WshShell.CreateShortcut((Join-Path $StartMenuDir "Sentinel Antivirus Dashboard.lnk"))
$StartShortcut.TargetPath = $GuiExe
$StartShortcut.WorkingDirectory = $InstallDir
$StartShortcut.Description = "Sentinel Antivirus Control Center"
$StartShortcut.Save()

# Desktop Shortcut
if (-not $NoDesktopShortcut) {
    $DesktopPath = [System.Environment]::GetFolderPath([System.Environment+SpecialFolder]::CommonDesktopDirectory)
    $DeskShortcut = $WshShell.CreateShortcut((Join-Path $DesktopPath "Sentinel Antivirus.lnk"))
    $DeskShortcut.TargetPath = $GuiExe
    $DeskShortcut.WorkingDirectory = $InstallDir
    $DeskShortcut.Description = "Sentinel Antivirus Control Center"
    $DeskShortcut.Save()
}
Write-Host "      Shortcuts created successfully." -ForegroundColor Green

# 6. Start Service & Tray
if (-not $NoStartService) {
    Write-Host "[6/6] Starting Sentinel Antivirus Protection..." -ForegroundColor Cyan
    Start-Service -Name "SentinelService"
    Write-Host "      SentinelService is RUNNING (NT AUTHORITY\SYSTEM)." -ForegroundColor Green

    # Launch tray app in current user session
    Start-Process -FilePath $TrayExe -WorkingDirectory $InstallDir
    Write-Host "      Sentinel Tray Companion launched in Taskbar." -ForegroundColor Green
}

Write-Host "==================================================================" -ForegroundColor Green
Write-Host "     SENTINEL ANTIVIRUS SUCCESSFULLY INSTALLED & ACTIVE           " -ForegroundColor Green
Write-Host "==================================================================" -ForegroundColor Green
Write-Host "  Dashboard:     Start Menu -> Sentinel Antivirus Dashboard"
Write-Host "  System Tray:   Look for shield icon in taskbar near clock"
Write-Host "  Service:       Get-Service SentinelService"
Write-Host "  CLI:           `"$InstallDir\sentinel_cli.exe`" status"
Write-Host "==================================================================" -ForegroundColor Green
