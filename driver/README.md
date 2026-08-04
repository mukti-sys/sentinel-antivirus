# Sentinel Minifilter Driver — Development Guide

## ⚠️ SAFETY RULES

1. **ALL kernel work happens inside a VM** (Hyper-V or VMware)
2. **NEVER load the driver on your host laptop**
3. **ALWAYS snapshot the VM** before each `fltmc load` attempt
4. A bug in `SfPreCreate` can **hang the entire OS** (not just BSOD), because every file open routes through the minifilter
5. If the VM hangs, **revert to the snapshot** — do not try to recover

## VM Setup

### 1. Create VM
- Hyper-V or VMware, **Windows 11 x64**
- At least 4 GB RAM, 40 GB disk
- Mount the project directory as a read-only shared folder

### 2. Install Build Tools (inside VM)
1. Download [Visual Studio 2022 Community](https://visualstudio.microsoft.com/downloads/)
2. In the installer, select:
   - "Desktop development with C++"
   - Individual components: "Windows 11 SDK"
3. Download [Windows Driver Kit (WDK)](https://learn.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk)
4. Install the WDK VS extension

### 3. Enable Test Signing (inside VM)
```powershell
# Run as Administrator:
.\scripts\enable_test_signing.ps1
# Restart the VM
```

### 4. Create Test Certificate
```powershell
# Run as Administrator:
.\scripts\setup_signing.ps1
```

### 5. Disable Secure Boot
- VM Settings → Security → Uncheck "Enable Secure Boot"

## Building

Open a **VS 2022 Developer Command Prompt** in the VM:

```cmd
cd driver\SentinelFilter
msbuild SentinelFilter.vcxproj /p:Configuration=Debug /p:Platform=x64
```

## Installing

```powershell
# Run as Administrator, AFTER taking a VM snapshot:
.\scripts\install_driver.ps1
```

## Verifying

```cmd
fltmc
```
You should see `SentinelFilter` with altitude `328100`.

## Uninstalling

```powershell
.\scripts\uninstall_driver.ps1
```

## Testing the DoD

```cmd
# In the VM, after driver is loaded:
python -m sentinel.tests.verify_live_phase4
```

## Architecture

```
SentinelFilter.sys (kernel)
├── SentinelFilter.c    — DriverEntry, SfPreCreate callback
├── communication.c     — Filter communication port
├── blocklist.c         — Portable path blocklist (shared with user-mode test)
├── blocklist.h         — Portable header
├── SentinelFilter.h    — Shared message structures
├── SentinelFilter.inf  — Installation INF
└── SentinelFilter.vcxproj — Build project

sentinel/kernel/ (user-mode, Python)
├── bridge.py           — fltlib.dll ctypes wrapper
└── messages.py         — ctypes structures matching SentinelFilter.h
```

## Altitude

- **328100** — FSFilter Anti-Virus range (320000–329998)
- For production: request from Microsoft (`fsfcomm@microsoft.com`)
- For personal dev/test-signing: any unused value in range works
