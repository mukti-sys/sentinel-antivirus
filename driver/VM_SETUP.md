# Phase 4 — VM Setup Guide (VirtualBox)

## Your System
- **RAM:** 23 GB — can safely allocate 6–8 GB to VM
- **Disk:** 658 GB free — VM needs ~60 GB
- **CPU:** Virtualization firmware enabled ✓
- **Host OS:** Windows 11 Home (no Hyper-V Manager, but hypervisor is active)

---

## Step 1: Install VirtualBox

1. Download from https://www.virtualbox.org/wiki/Downloads
   - Click **"Windows hosts"** to get the installer
2. Run the installer with default settings
3. Reboot if prompted

**Note:** VirtualBox may conflict with WSL2/Hyper-V. If you use WSL2,
check "Use Hyper-V" in VirtualBox settings (VirtualBox 7+ supports this).

---

## Step 2: Get a Windows 11 ISO

Download directly from Microsoft:
- https://www.microsoft.com/software-download/windows11
- Click **"Download Windows 11 Disk Image (ISO)"**
- Select "Windows 11 (multi-edition ISO)" → Download

---

## Step 3: Create the VM

In VirtualBox Manager:

1. Click **"New"**
2. Configure:
   - **Name:** `SentinelDriver`
   - **Type:** Microsoft Windows
   - **Version:** Windows 11 (64-bit)
3. **Hardware:**
   - **RAM:** 6144 MB (6 GB)
   - **Processors:** 4 CPUs
   - **Enable EFI:** check
4. **Hard Disk:**
   - Create virtual hard disk
   - **Size:** 60 GB (dynamically allocated)
   - **Type:** VDI
5. Click **Create**

### Critical VM Settings (before first boot):

Go to **Settings** for the VM:

- **System > Motherboard:**
  - Enable EFI: checked
  - Uncheck "Enable Secure Boot" (required for test-signing!)
- **System > Processor:**
  - Enable PAE/NX: checked
- **Display:**
  - Video Memory: 128 MB
  - Graphics Controller: VBoxSVGA
- **Storage:**
  - Click the empty CD icon > choose the Windows 11 ISO
- **Shared Folders:**
  - Add a shared folder:
    - **Folder Path:** `C:\Users\littlemukti\OneDrive\Documents\pgt app\antivirus`
    - **Folder Name:** `antivirus`
    - **Read-only:** checked (IMPORTANT — never write to host from VM)
    - **Auto-mount:** checked
    - **Mount point:** `Z:`

---

## Step 4: Install Windows 11 in the VM

1. Start the VM
2. Boot from the ISO
3. Install Windows 11 (any edition — Home is fine for this)
4. **Skip the Microsoft account requirement:**
   - At the "Let's connect you to a network" screen:
   - Press `Shift+F10` to open Command Prompt
   - Type: `oobe\bypassnro`
   - The VM will restart — now select "I don't have internet"
5. Create a local account (e.g., `sentinel`)
6. After setup, install **VirtualBox Guest Additions:**
   - In the VM menu bar: Devices > Insert Guest Additions CD
   - Run the installer from the virtual CD drive
   - Reboot the VM

---

## Step 5: Take a CLEAN Snapshot

After Windows is installed and Guest Additions are working:

1. In VirtualBox Manager: **Machine > Take Snapshot**
2. Name it: `Clean Windows Install`
3. This is your "factory reset" point

---

## Step 6: Install VS 2022 + WDK (inside VM)

### Install Visual Studio 2022 Community:

1. Download from https://visualstudio.microsoft.com/downloads/
2. In the installer, select:
   - Check **"Desktop development with C++"**
   - In "Individual components", also check:
     - **"Windows 11 SDK (latest version)"**
     - **"MSVC v143 - VS 2022 C++ x64/x86 build tools"**
3. Install (this takes 10-20 minutes)

### Install Windows Driver Kit (WDK):

1. Download the WDK from https://learn.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk
2. Run the WDK installer
3. When prompted, install the **WDK Visual Studio extension**
4. Reboot the VM

### Take another snapshot:

1. **Machine > Take Snapshot**
2. Name it: `VS2022 + WDK Installed`

---

## Step 7: Enable Test Signing + Create Certificate

Open **PowerShell as Administrator** inside the VM:

```powershell
# Navigate to the shared folder
cd Z:\driver\scripts

# Enable test signing (requires reboot)
.\enable_test_signing.ps1

# After reboot, create the test certificate
.\setup_signing.ps1
```

Verify test signing is active — you should see a **"Test Mode"** watermark
in the bottom-right corner of the VM desktop.

### Take snapshot:

1. **Machine > Take Snapshot**
2. Name it: `Test Signing Ready`

---

## Step 8: Build the Driver

Open **"Developer Command Prompt for VS 2022"** (NOT regular CMD):

```cmd
cd Z:\driver\SentinelFilter
msbuild SentinelFilter.vcxproj /p:Configuration=Debug /p:Platform=x64
```

If building from the shared folder (Z:) has issues, copy the `driver\`
directory to the VM's local C: drive first, then build there.

---

## Step 9: SNAPSHOT BEFORE LOADING

**Take a snapshot now:**

1. **Machine > Take Snapshot**
2. Name it: `Before First Driver Load`

If the driver hangs the VM, you revert to this snapshot.

---

## Step 10: Install and Load the Driver

Open **PowerShell as Administrator** inside the VM:

```powershell
cd Z:\driver\scripts
.\install_driver.ps1
```

Verify: `fltmc` should show `SentinelFilter` with altitude `328100`.

### If the VM hangs or BSODs:
1. In VirtualBox: **Machine > Close > Power Off**
2. **Machine > Snapshots > Restore "Before First Driver Load"**
3. Debug, rebuild, and try again

---

## Step 11: Run the DoD Test

```cmd
cd Z:
python -m sentinel.tests.verify_live_phase4
```

---

## Snapshot Strategy

| Snapshot Name | When | Purpose |
|---|---|---|
| `Clean Windows Install` | After Step 4 | Factory reset |
| `VS2022 + WDK Installed` | After Step 6 | Before any driver work |
| `Test Signing Ready` | After Step 7 | Before builds |
| `Before First Driver Load` | After Step 9 | Before every fltmc load |
| `Driver Loaded Successfully` | After Step 10 works | Stable working state |
