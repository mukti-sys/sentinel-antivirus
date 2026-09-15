#!/usr/bin/env python3
"""Sentinel Antivirus Automated Distribution Builder.

Compiles standalone Windows executables using PyInstaller and packages
the complete installer and binary bundle:
  - dist/Sentinel/sentinel_service.exe
  - dist/Sentinel/sentinel_tray.exe
  - dist/Sentinel/sentinel_gui.exe
  - dist/Sentinel/sentinel_cli.exe
  - dist/Sentinel-Antivirus-v2.0-Setup.zip
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import time
import zipfile
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
DIST_DIR = PROJECT_ROOT / "dist"
BUILD_DIR = PROJECT_ROOT / "build"
SENTINEL_DIST = DIST_DIR / "Sentinel"
SPEC_FILE = PROJECT_ROOT / "sentinel.spec"
MODEL_FILE = PROJECT_ROOT / "sentinel" / "data" / "pe_model_v2.joblib"


def check_prerequisites() -> bool:
    """Ensure all required model and configuration files exist prior to compilation."""
    print("[*] Checking build prerequisites...")
    if not MODEL_FILE.exists():
        print(f"[-] Missing 5M PE model file: {MODEL_FILE}")
        print("    Run 'python sentinel/engine/train_large_scale.py' first.")
        return False

    rules_dir = PROJECT_ROOT / "sentinel" / "config" / "rules"
    yar_files = list(rules_dir.glob("*.yar"))
    if not yar_files:
        print(f"[-] No YARA rule files found in {rules_dir}")
        return False

    print(f"    [+] Pre-trained model: {MODEL_FILE.name} ({MODEL_FILE.stat().st_size / (1024*1024):.2f} MB)")
    print(f"    [+] YARA rules: {len(yar_files)} rule files verified")
    return True


def clean_previous_builds() -> None:
    """Remove previous build and dist artifacts."""
    print("[*] Cleaning previous build artifacts...")
    if BUILD_DIR.exists():
        try:
            shutil.rmtree(BUILD_DIR)
        except Exception as exc:
            print(f"    [!] Could not cleanly remove {BUILD_DIR}: {exc}")
    if SENTINEL_DIST.exists():
        try:
            shutil.rmtree(SENTINEL_DIST)
        except Exception as exc:
            print(f"    [!] Could not cleanly remove {SENTINEL_DIST}: {exc}")


def run_pyinstaller() -> bool:
    """Invoke PyInstaller on sentinel.spec."""
    print(f"[*] Compiling native Windows executables via PyInstaller ({SPEC_FILE.name})...")
    start_t = time.time()

    cmd = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--clean",
        "--noconfirm",
        str(SPEC_FILE),
    ]

    res = subprocess.run(cmd, cwd=str(PROJECT_ROOT))
    if res.returncode != 0:
        print(f"[-] PyInstaller failed with exit code {res.returncode}")
        return False

    elapsed = time.time() - start_t
    print(f"[+] Compilation completed in {elapsed:.1f} seconds.")
    return True


def copy_deployment_helpers() -> None:
    """Copy PowerShell installer, uninstaller, and service scripts into dist/Sentinel."""
    print("[*] Bundling installer scripts and configuration files...")
    files_to_copy = [
        ("Install-Sentinel.ps1", "Install-Sentinel.ps1"),
        ("Uninstall-Sentinel.ps1", "Uninstall-Sentinel.ps1"),
        ("service_manager.ps1", "service_manager.ps1"),
        ("README.md", "README.md"),
    ]

    for src_name, dst_name in files_to_copy:
        src = PROJECT_ROOT / src_name
        if src.exists():
            shutil.copy2(src, SENTINEL_DIST / dst_name)
            print(f"    [+] Bundled: {dst_name}")

    # Copy driver binaries if compiled
    driver_sys = PROJECT_ROOT / "driver" / "SentinelFilter" / "x64" / "Debug" / "SentinelFilter.sys"
    driver_inf = PROJECT_ROOT / "driver" / "SentinelFilter" / "SentinelFilter.inf"
    if driver_sys.exists():
        driver_dir = SENTINEL_DIST / "driver"
        driver_dir.mkdir(parents=True, exist_ok=True)
        shutil.copy2(driver_sys, driver_dir / "SentinelFilter.sys")
        if driver_inf.exists():
            shutil.copy2(driver_inf, driver_dir / "SentinelFilter.inf")
        print("    [+] Bundled: Kernel Minifilter Driver (SentinelFilter.sys)")


def create_zip_package() -> Path:
    """Create a clean standalone zip distribution package."""
    zip_path = DIST_DIR / "Sentinel-Antivirus-v2.0-Setup.zip"
    print(f"[*] Packaging distribution ZIP: {zip_path.name}...")

    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        for file in SENTINEL_DIST.rglob("*"):
            if file.is_file():
                arcname = file.relative_to(SENTINEL_DIST)
                zf.write(file, arcname=str(Path("Sentinel") / arcname))

    zip_size_mb = zip_path.stat().st_size / (1024 * 1024)
    print(f"[+] Successfully created package: {zip_path.name} ({zip_size_mb:.2f} MB)")
    return zip_path


def audit_distribution() -> None:
    """Print complete summary of generated executables and assets."""
    print("\n" + "=" * 75)
    print("           SENTINEL ANTIVIRUS DISTRIBUTION BUILD AUDIT           ")
    print("=" * 75)

    expected_exes = [
        ("sentinel_service.exe", "Core Background Service (NT AUTHORITY\\SYSTEM)"),
        ("sentinel_tray.exe",    "System Tray Companion (Taskbar & Toasts)"),
        ("sentinel_gui.exe",     "Desktop GUI Dashboard (Sandbox / Memory / Network)"),
        ("sentinel_cli.exe",     "Command-Line Administrative Utility"),
    ]

    for exe_name, desc in expected_exes:
        exe_p = SENTINEL_DIST / exe_name
        if exe_p.exists():
            sz_mb = exe_p.stat().st_size / (1024 * 1024)
            print(f"  [OK] {exe_name:24} ({sz_mb:5.2f} MB) - {desc}")
        else:
            print(f"  [MISSING] {exe_name:20} - {desc}")

    # Check model bundle
    bundled_model = SENTINEL_DIST / "_internal" / "sentinel" / "data" / "pe_model_v2.joblib"
    if not bundled_model.exists():
        bundled_model = SENTINEL_DIST / "sentinel" / "data" / "pe_model_v2.joblib"

    if bundled_model.exists():
        print(f"  [OK] Bundled PE Model v2      ({bundled_model.stat().st_size / (1024*1024):5.2f} MB) - 5,000,000 Trained Samples")
    else:
        print("  [?] Bundled PE Model v2 embedded in archive")

    print("-" * 75)
    print(f"  Target Installation Path: C:\\Program Files\\Sentinel Antivirus")
    print(f"  Installer Script:         {SENTINEL_DIST / 'Install-Sentinel.ps1'}")
    print(f"  Uninstaller Script:       {SENTINEL_DIST / 'Uninstall-Sentinel.ps1'}")
    print("=" * 75 + "\n")


def main() -> int:
    if not check_prerequisites():
        return 1

    clean_previous_builds()

    if not run_pyinstaller():
        return 1

    copy_deployment_helpers()
    create_zip_package()
    audit_distribution()
    return 0


if __name__ == "__main__":
    sys.exit(main())
