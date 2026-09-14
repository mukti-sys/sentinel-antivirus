<#
.SYNOPSIS
    Sentinel Antivirus — Windows Service Manager (NT AUTHORITY\SYSTEM & Watchdog).
.DESCRIPTION
    Installs, configures, manages, and queries Sentinel Core Service.
    Configures SCM auto-start on boot, SYSTEM account execution, and automatic
    crash watchdog restart (failure actions).
.EXAMPLE
    .\service_manager.ps1 -Install
    .\service_manager.ps1 -Start
    .\service_manager.ps1 -Status
    .\service_manager.ps1 -Stop
    .\service_manager.ps1 -Uninstall
#>

[CmdletBinding()]
param(
    [switch]$Install,
    [switch]$Uninstall,
    [switch]$Start,
    [switch]$Stop,
    [switch]$Restart,
    [switch]$Status
)

$ServiceName = "SentinelCoreSvc"
$ServiceDisplayName = "Sentinel Core Detection Service"
$ServiceDescription = "Next-Generation behavioral antivirus service: honeypots, kernel minifilter driver, and real-time heuristics."
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$PythonExe = Join-Path $ScriptDir ".venv\Scripts\python.exe"

if (-not (Test-Path $PythonExe)) {
    $PythonExe = (Get-Command python.exe -ErrorAction SilentlyContinue).Source
}

function Assert-Administrator {
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Error "[!] Administrator privileges required. Please run this script in an elevated PowerShell terminal."
        exit 1
    }
}

function Install-SentinelService {
    Assert-Administrator
    Write-Host "[+] Installing $ServiceDisplayName ($ServiceName)..." -ForegroundColor Cyan

    # Path to service runner
    $BinPath = "`"$PythonExe`" -m sentinel.service"

    # Register with Service Control Manager (SCM) under NT AUTHORITY\SYSTEM
    & sc.exe create $ServiceName binPath= $BinPath start= auto obj= "NT AUTHORITY\SYSTEM" DisplayName= $ServiceDisplayName
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Failed to create service via sc.exe"
        return
    }

    # Set service description
    & sc.exe description $ServiceName $ServiceDescription

    # Configure Watchdog Failure Actions:
    # 1st failure: restart after 5s
    # 2nd failure: restart after 10s
    # Subsequent failures: restart after 30s
    # Reset fail counter after 1 day (86400s)
    Write-Host "[+] Configuring SCM watchdog recovery actions..." -ForegroundColor Cyan
    & sc.exe failure $ServiceName reset= 86400 actions= restart/5000/restart/10000/restart/30000

    Write-Host "[OK] Sentinel Service successfully installed and configured for boot-time SYSTEM protection!" -ForegroundColor Green
}

function Start-SentinelService {
    Assert-Administrator
    Write-Host "[+] Starting $ServiceName..." -ForegroundColor Cyan
    & sc.exe start $ServiceName
}

function Stop-SentinelService {
    Assert-Administrator
    Write-Host "[+] Stopping $ServiceName..." -ForegroundColor Cyan
    & sc.exe stop $ServiceName
}

function Uninstall-SentinelService {
    Assert-Administrator
    Write-Host "[+] Stopping and removing $ServiceName..." -ForegroundColor Yellow
    & sc.exe stop $ServiceName 2>$null
    Start-Sleep -Seconds 1
    & sc.exe delete $ServiceName
    Write-Host "[OK] Service removed." -ForegroundColor Green
}

function Get-SentinelStatus {
    Write-Host "=== Sentinel Service Status ===" -ForegroundColor Cyan
    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($null -eq $svc) {
        Write-Host "Service '$ServiceName': NOT INSTALLED" -ForegroundColor Red
        return
    }

    $statusColor = if ($svc.Status -eq "Running") { "Green" } else { "Yellow" }
    Write-Host "SCM Status       : $($svc.Status)" -ForegroundColor $statusColor
    Write-Host "Startup Type     : $($svc.StartType)" -ForegroundColor Gray


    # Query live IPC pipe
    Write-Host "`n=== Querying Named Pipe IPC (\\.\pipe\SentinelIPC) ===" -ForegroundColor Cyan
    $ipcCmd = @"
from sentinel.ipc import NamedPipeClient
client = NamedPipeClient()
if client.is_service_running():
    status = client.get_status()
    print('IPC Connection   : CONNECTED (Session 0 bridge active)')
    print(f'Protection Shield: {status.get(\"shield\", \"UNKNOWN\")}')
    canaries = status.get('canary_traps', {})
    print(f'Canary Traps     : {canaries.get(\"armed_traps\", 0)} armed honeypots')
    driver = status.get('kernel_driver', {})
    driver_state = 'CONNECTED' if driver.get('connected') else 'NOT LOADED (User-mode only)'
    print(f'Kernel Minifilter: {driver_state}')
else:
    print('IPC Connection   : Service not listening on named pipe.')
"@
    & $PythonExe -c $ipcCmd
}

# Main Execution Dispatcher
if ($Install) {
    Install-SentinelService
} elseif ($Uninstall) {
    Uninstall-SentinelService
} elseif ($Start) {
    Start-SentinelService
} elseif ($Stop) {
    Stop-SentinelService
} elseif ($Restart) {
    Stop-SentinelService
    Start-Sleep -Seconds 2
    Start-SentinelService
} elseif ($Status) {
    Get-SentinelStatus
} else {
    Get-SentinelStatus
}
