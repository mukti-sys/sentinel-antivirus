<#
.SYNOPSIS
    Installs or uninstalls Sentinel Antivirus autostart on Windows logon.
.DESCRIPTION
    Adds Sentinel to HKCU\Software\Microsoft\Windows\CurrentVersion\Run so
    the protection service and tray/dashboard start automatically when you log in.
    Runs entirely in user-space with zero UAC elevation required.
#>
param(
    [switch]$Uninstall,
    [switch]$Status
)

$RegPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
$ValueName = "SentinelAntivirus"

$RepoRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$VenvPython = Join-Path $RepoRoot ".venv\Scripts\pythonw.exe"
if (-not (Test-Path $VenvPython)) {
    $VenvPython = Join-Path $RepoRoot ".venv\Scripts\python.exe"
}
$MainScript = Join-Path $RepoRoot "sentinel_main.py"
$Command = "`"$VenvPython`" `"$MainScript`""

if ($Status) {
    $Current = Get-ItemProperty -Path $RegPath -Name $ValueName -ErrorAction SilentlyContinue
    if ($Current) {
        Write-Host "Sentinel Autostart: ENABLED" -ForegroundColor Green
        Write-Host "Command: $($Current.$ValueName)" -ForegroundColor Gray
    } else {
        Write-Host "Sentinel Autostart: DISABLED" -ForegroundColor Yellow
    }
    return
}

if ($Uninstall) {
    Remove-ItemProperty -Path $RegPath -Name $ValueName -ErrorAction SilentlyContinue
    Write-Host "Sentinel autostart successfully removed from Windows startup." -ForegroundColor Green
    return
}

# Install
Set-ItemProperty -Path $RegPath -Name $ValueName -Value $Command
Write-Host "Sentinel autostart successfully registered!" -ForegroundColor Green
Write-Host "Target: $Command" -ForegroundColor Gray
Write-Host "Sentinel will now automatically start protection whenever you log into Windows." -ForegroundColor Cyan
