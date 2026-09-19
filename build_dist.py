#!/usr/bin/env python3
"""Sentinel Antivirus Cross-Platform Distribution Builder.

Compiles standalone executables using PyInstaller and packages
the complete installer and binary bundle for each platform.

Usage:
    python build_dist.py                    # Build for current platform
    python build_dist.py --target linux     # Build Linux distribution
    python build_dist.py --target macos     # Build macOS distribution
    python build_dist.py --target windows   # Build Windows distribution

Platform targets:
  Windows: dist/Sentinel/sentinel_service.exe, sentinel_tray.exe, sentinel_gui.exe, sentinel_cli.exe
  Linux:   dist/Sentinel/sentinel_service, sentinel_gui, sentinel_cli
  macOS:   dist/Sentinel/sentinel_service, sentinel_gui, sentinel_cli
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import time
import zipfile
from pathlib import Path

VERSION = "2.2"
PROJECT_ROOT = Path(__file__).resolve().parent
DIST_DIR = PROJECT_ROOT / "dist"
BUILD_DIR = PROJECT_ROOT / "build"
SENTINEL_DIST = DIST_DIR / "Sentinel"
MODEL_FILE = PROJECT_ROOT / "sentinel" / "data" / "pe_model_ember.model"
LEGACY_MODEL = PROJECT_ROOT / "sentinel" / "data" / "pe_model_v2.joblib"

# Platform-specific spec files
SPEC_FILES = {
    "windows": PROJECT_ROOT / "sentinel.spec",
    "linux": PROJECT_ROOT / "sentinel.linux.spec",
    "macos": PROJECT_ROOT / "sentinel.macos.spec",
    "darwin": PROJECT_ROOT / "sentinel.macos.spec",
}


def detect_platform() -> str:
    """Detect the current build platform."""
    if sys.platform == "win32":
        return "windows"
    elif sys.platform == "linux":
        return "linux"
    elif sys.platform == "darwin":
        return "macos"
    return sys.platform


def check_prerequisites() -> bool:
    """Ensure all required model and configuration files exist prior to compilation."""
    print("[*] Checking build prerequisites...")
    active_model = MODEL_FILE if MODEL_FILE.exists() else LEGACY_MODEL
    if not active_model.exists():
        print(f"[-] Missing PE model file: {MODEL_FILE}")
        return False

    rules_dir = PROJECT_ROOT / "sentinel" / "config" / "rules"
    yar_files = list(rules_dir.glob("*.yar"))
    if not yar_files:
        print(f"[-] No YARA rule files found in {rules_dir}")
        return False

    print(f"    [+] Pre-trained model: {active_model.name} ({active_model.stat().st_size / (1024*1024):.2f} MB)")
    print(f"    [+] YARA rules: {len(yar_files)} rule files verified")
    return True


def _force_remove_tree(path: Path) -> None:
    """Recursively remove a directory tree, clearing read-only attributes on Windows."""
    if not path.exists():
        return
    import stat
    if sys.platform == "win32":
        try:
            subprocess.run(["attrib", "-r", "-s", "-h", f"{path}\\*", "/s", "/d"], capture_output=True)
            subprocess.run(["attrib", "-r", "-s", "-h", str(path)], capture_output=True)
        except Exception:
            pass

    def _on_error(func, p, exc_info):
        try:
            os.chmod(p, stat.S_IWRITE)
            func(p)
        except Exception:
            pass

    try:
        shutil.rmtree(path, onerror=_on_error)
    except Exception as exc:
        print(f"    [!] Warning removing {path}: {exc}")


def clean_previous_builds() -> None:
    """Remove previous build and dist artifacts."""
    print("[*] Cleaning previous build artifacts...")
    if BUILD_DIR.exists():
        _force_remove_tree(BUILD_DIR)
    if SENTINEL_DIST.exists():
        _force_remove_tree(SENTINEL_DIST)


def compile_native_core() -> None:
    """Compile native sentinel_core acceleration library if cargo is installed."""
    build_script = PROJECT_ROOT / "build_native.py"
    if build_script.exists():
        print("[*] Checking native Rust acceleration core compilation...")
        try:
            res = subprocess.run([sys.executable, str(build_script)], cwd=str(PROJECT_ROOT))
            if res.returncode == 0:
                print("[+] Native sentinel_core built successfully.")
            else:
                print("[!] Native core build skipped/failed; continuing with pure-Python fallback.")
        except Exception as exc:
            print(f"[!] Warning running build_native: {exc}")


def run_pyinstaller(target: str) -> bool:
    """Invoke PyInstaller on the platform-appropriate spec file."""
    spec_file = SPEC_FILES.get(target)
    if not spec_file or not spec_file.exists():
        print(f"[-] No spec file found for target '{target}': {spec_file}")
        return False

    print(f"[*] Compiling native {target} executables via PyInstaller ({spec_file.name})...")
    start_t = time.time()

    cmd = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--clean",
        "--noconfirm",
        str(spec_file),
    ]

    res = subprocess.run(cmd, cwd=str(PROJECT_ROOT))
    if res.returncode != 0:
        print(f"[-] PyInstaller failed with exit code {res.returncode}")
        return False

    elapsed = time.time() - start_t
    print(f"[+] Compilation completed in {elapsed:.1f} seconds.")
    return True


def copy_deployment_helpers(target: str) -> None:
    """Copy platform-appropriate installer scripts and config files."""
    print("[*] Bundling installer scripts and configuration files...")

    if target == "windows":
        files_to_copy = [
            ("Install-Sentinel.ps1", "Install-Sentinel.ps1"),
            ("Uninstall-Sentinel.ps1", "Uninstall-Sentinel.ps1"),
            ("service_manager.ps1", "service_manager.ps1"),
            ("README.md", "README.md"),
            ("dist/RELEASE_NOTES.md", "RELEASE_NOTES.md"),
        ]
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

    elif target == "linux":
        files_to_copy = [
            ("install/install-sentinel.sh", "install-sentinel.sh"),
            ("README.md", "README.md"),
        ]

    elif target in ("macos", "darwin"):
        files_to_copy = [
            ("install/install-sentinel-macos.sh", "install-sentinel.sh"),
            ("README.md", "README.md"),
        ]

    else:
        files_to_copy = [("README.md", "README.md")]

    for src_name, dst_name in files_to_copy:
        src = PROJECT_ROOT / src_name
        if src.exists():
            shutil.copy2(src, SENTINEL_DIST / dst_name)
            print(f"    [+] Bundled: {dst_name}")

    # Make shell scripts executable
    for sh in SENTINEL_DIST.glob("*.sh"):
        os.chmod(str(sh), 0o755)


def create_package(target: str) -> Path:
    """Create a platform-appropriate distribution package."""
    if target == "windows":
        return _create_zip_package(f"Sentinel-Antivirus-v{VERSION}-Windows-Setup.zip")
    elif target == "linux":
        return _create_tar_package(f"Sentinel-Antivirus-v{VERSION}-Linux-x86_64.tar.gz")
    elif target in ("macos", "darwin"):
        return _create_tar_package(f"Sentinel-Antivirus-v{VERSION}-macOS-Universal.tar.gz")
    return _create_zip_package(f"Sentinel-Antivirus-v{VERSION}-Setup.zip")


def _create_zip_package(filename: str) -> Path:
    """Create a ZIP distribution package."""
    zip_path = DIST_DIR / filename
    print(f"[*] Packaging ZIP: {zip_path.name}...")

    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        for file in SENTINEL_DIST.rglob("*"):
            if file.is_file():
                arcname = file.relative_to(SENTINEL_DIST)
                zf.write(file, arcname=str(Path("Sentinel") / arcname))

    size_mb = zip_path.stat().st_size / (1024 * 1024)
    print(f"[+] Package created: {zip_path.name} ({size_mb:.2f} MB)")
    return zip_path


def _create_tar_package(filename: str) -> Path:
    """Create a tar.gz distribution package."""
    import tarfile
    tar_path = DIST_DIR / filename
    print(f"[*] Packaging tar.gz: {tar_path.name}...")

    with tarfile.open(tar_path, "w:gz", compresslevel=9) as tf:
        for file in SENTINEL_DIST.rglob("*"):
            if file.is_file():
                arcname = str(Path("Sentinel") / file.relative_to(SENTINEL_DIST))
                tf.add(file, arcname=arcname)

    size_mb = tar_path.stat().st_size / (1024 * 1024)
    print(f"[+] Package created: {tar_path.name} ({size_mb:.2f} MB)")
    return tar_path


def audit_distribution(target: str) -> None:
    """Print complete summary of generated executables and assets."""
    print("\n" + "=" * 75)
    print(f"     SENTINEL ANTIVIRUS v{VERSION} DISTRIBUTION BUILD AUDIT ({target.upper()})     ")
    print("=" * 75)

    ext = ".exe" if target == "windows" else ""

    if target == "windows":
        expected_exes = [
            (f"sentinel_service{ext}", "Core Background Service (NT AUTHORITY\\SYSTEM)"),
            (f"sentinel_tray{ext}",    "System Tray Companion (Taskbar & Toasts)"),
            (f"sentinel_gui{ext}",     "Desktop GUI Dashboard (Sandbox / Memory / Network)"),
            (f"sentinel_cli{ext}",     "Command-Line Administrative Utility"),
        ]
    else:
        expected_exes = [
            (f"sentinel_service{ext}", f"Background Daemon ({'systemd' if target == 'linux' else 'launchd'})"),
            (f"sentinel_gui{ext}",     "Desktop GUI Dashboard (Tk)"),
            (f"sentinel_cli{ext}",     "Command-Line Administrative Utility"),
        ]

    for exe_name, desc in expected_exes:
        exe_p = SENTINEL_DIST / exe_name
        if exe_p.exists():
            sz_mb = exe_p.stat().st_size / (1024 * 1024)
            print(f"  [OK] {exe_name:24} ({sz_mb:5.2f} MB) - {desc}")
        else:
            print(f"  [MISSING] {exe_name:20} - {desc}")

    # Check bundled model
    bundled_ember = SENTINEL_DIST / "_internal" / "sentinel" / "data" / "pe_model_ember.model"
    if not bundled_ember.exists():
        bundled_ember = SENTINEL_DIST / "sentinel" / "data" / "pe_model_ember.model"

    if bundled_ember.exists():
        print(f"  [OK] Bundled EMBER2024 Model  ({bundled_ember.stat().st_size / (1024*1024):5.2f} MB) - 3.23M Real Samples (KDD 2025)")
    else:
        bundled_model = SENTINEL_DIST / "_internal" / "sentinel" / "data" / "pe_model_v2.joblib"
        if not bundled_model.exists():
            bundled_model = SENTINEL_DIST / "sentinel" / "data" / "pe_model_v2.joblib"
        if bundled_model.exists():
            print(f"  [OK] Bundled PE Model v2      ({bundled_model.stat().st_size / (1024*1024):5.2f} MB) - Baseline Fallback Model")
        else:
            print("  [?] Bundled PE Model embedded in archive")

    # Check native core acceleration library
    core_names = ["sentinel_core.dll", "libsentinel_core.so", "libsentinel_core.dylib"]
    found_core = any((SENTINEL_DIST / name).exists() or (SENTINEL_DIST / "sentinel" / "engine" / name).exists() or (SENTINEL_DIST / "_internal" / "sentinel" / "engine" / name).exists() for name in core_names)
    if found_core:
        print("  [OK] Native Core (sentinel_core) - SIMD Hashing, Fast PE & Parallel Rayon Scanner")
    else:
        print("  [INFO] Pure-Python Engine Mode (Native Core optional)")

    print("-" * 75)
    if target == "windows":
        print(f"  Target Installation:  C:\\Program Files\\Sentinel Antivirus")
        print(f"  Installer Script:     Install-Sentinel.ps1")
    elif target == "linux":
        print(f"  Target Installation:  /opt/sentinel")
        print(f"  Installer Script:     sudo bash install-sentinel.sh")
        print(f"  systemd service:      sentinel.service (auto-generated)")
    elif target in ("macos", "darwin"):
        print(f"  Target Installation:  /usr/local/sentinel")
        print(f"  Installer Script:     bash install-sentinel.sh")
        print(f"  launchd agent:        com.sentinel.antivirus.plist (auto-generated)")
    print("=" * 75 + "\n")


def main() -> int:
    parser = argparse.ArgumentParser(description="Sentinel Antivirus Distribution Builder")
    parser.add_argument(
        "--target", "-t",
        choices=["windows", "linux", "macos", "all"],
        default=None,
        help="Target platform (default: auto-detect current platform)",
    )
    args = parser.parse_args()

    target = args.target or detect_platform()

    if target == "all":
        current = detect_platform()
        print(f"[!] 'all' target only builds for current platform ({current}).")
        print(f"    Cross-compilation requires building on each target OS.")
        target = current

    print(f"[*] Target platform: {target}")
    print(f"[*] Version: v{VERSION}")

    if not check_prerequisites():
        return 1

    clean_previous_builds()
    compile_native_core()

    if not run_pyinstaller(target):
        return 1

    copy_deployment_helpers(target)
    create_package(target)
    audit_distribution(target)
    return 0


if __name__ == "__main__":
    sys.exit(main())
