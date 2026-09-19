#!/usr/bin/env python3
"""Build script for Sentinel native acceleration core (sentinel_core).

Compiles crates/sentinel_core into a native shared library (.dll, .so, or .dylib)
and copies it into sentinel/engine/ for runtime loading.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
CRATE_DIR = PROJECT_ROOT / "crates" / "sentinel_core"
ENGINE_DIR = PROJECT_ROOT / "sentinel" / "engine"
DIST_DIR = PROJECT_ROOT / "dist" / "Sentinel"


def build_native_core() -> Path | None:
    """Compile sentinel_core via cargo --release and place in sentinel/engine/."""
    cargo_path = shutil.which("cargo")
    if not cargo_path:
        print("[-] cargo not found in PATH. Skipping native compilation.")
        return None

    if not CRATE_DIR.exists():
        print(f"[-] Crate directory not found: {CRATE_DIR}")
        return None

    print(f"[*] Compiling native sentinel_core in {CRATE_DIR}...")
    cmd = [cargo_path, "build", "--release", "--manifest-path", str(CRATE_DIR / "Cargo.toml")]
    res = subprocess.run(cmd, cwd=str(PROJECT_ROOT))
    if res.returncode != 0:
        print(f"[-] cargo build failed with exit code {res.returncode}")
        return None

    target_dir = CRATE_DIR / "target" / "release"

    # Determine platform shared library name
    if sys.platform == "win32":
        lib_name = "sentinel_core.dll"
    elif sys.platform == "darwin":
        lib_name = "libsentinel_core.dylib"
    else:
        lib_name = "libsentinel_core.so"

    src_lib = target_dir / lib_name
    if not src_lib.exists():
        print(f"[-] Expected compiled library not found at: {src_lib}")
        return None

    dest_lib = ENGINE_DIR / lib_name
    shutil.copy2(src_lib, dest_lib)
    print(f"[+] Native library copied to: {dest_lib} ({dest_lib.stat().st_size / 1024:.1f} KB)")

    if DIST_DIR.exists():
        shutil.copy2(src_lib, DIST_DIR / lib_name)
        print(f"[+] Native library copied to: {DIST_DIR / lib_name}")

    return dest_lib


if __name__ == "__main__":
    out = build_native_core()
    sys.exit(0 if out else 1)
