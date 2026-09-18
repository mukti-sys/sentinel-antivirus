"""Cross-platform digital signature verification.

Abstracts signature verification across operating systems:
    - Windows: Authenticode via WinVerifyTrust (delegates to authenticode.py)
    - Linux:   GPG package signatures + ELF analysis via pefile/signify for PE
    - macOS:   codesign --verify for Mach-O / .app bundles

All platforms return a unified ``SignatureVerdict`` result.
"""
from __future__ import annotations

import logging
import subprocess
import sys
from pathlib import Path
from typing import NamedTuple

logger = logging.getLogger("sentinel.platform.signature")

_PLATFORM = sys.platform


class SignatureVerdict(NamedTuple):
    """Unified cross-platform signature verification result."""
    is_signed: bool
    is_valid: bool
    is_trusted: bool
    is_vendor_trusted: bool   # e.g. Microsoft on Windows, Apple on macOS, distro on Linux
    error_code: int
    error_description: str


def verify_signature(file_path: str | Path) -> SignatureVerdict:
    """Verify the digital signature of a file using the platform-native API.

    Returns a ``SignatureVerdict`` regardless of platform.
    """
    path = Path(file_path).resolve()
    if not path.is_file():
        return SignatureVerdict(
            is_signed=False, is_valid=False, is_trusted=False,
            is_vendor_trusted=False, error_code=-1,
            error_description="File not found",
        )

    if _PLATFORM == "win32":
        return _verify_windows(path)
    elif _PLATFORM == "linux":
        return _verify_linux(path)
    elif _PLATFORM == "darwin":
        return _verify_macos(path)
    else:
        return SignatureVerdict(
            is_signed=False, is_valid=False, is_trusted=False,
            is_vendor_trusted=False, error_code=-2,
            error_description=f"Unsupported platform: {_PLATFORM}",
        )


# ---------------------------------------------------------------------------
# Windows — delegate to existing Authenticode module
# ---------------------------------------------------------------------------
def _verify_windows(path: Path) -> SignatureVerdict:
    """Windows Authenticode verification via WinVerifyTrust."""
    try:
        from sentinel.engine.authenticode import verify_pe_signature
        av = verify_pe_signature(path)
        return SignatureVerdict(
            is_signed=av.is_signed,
            is_valid=av.is_valid,
            is_trusted=av.is_trusted,
            is_vendor_trusted=av.is_microsoft,
            error_code=av.error_code,
            error_description=av.error_description,
        )
    except Exception as exc:
        logger.debug("Windows signature check failed for %s: %s", path.name, exc)
        return SignatureVerdict(
            is_signed=False, is_valid=False, is_trusted=False,
            is_vendor_trusted=False, error_code=-1,
            error_description=str(exc),
        )


# ---------------------------------------------------------------------------
# Linux — dpkg-sig / rpm --checksig + ELF section check
# ---------------------------------------------------------------------------
def _verify_linux(path: Path) -> SignatureVerdict:
    """Linux signature verification.

    Strategy:
    1. For .deb packages: ``dpkg-sig --verify``
    2. For .rpm packages: ``rpm --checksig``
    3. For ELF binaries: check if the file is part of an installed package
       (dpkg -S or rpm -qf) which implies distro-signed.
    4. For PE files on Linux (malware scanning): use signify/pefile.
    """
    suffix = path.suffix.lower()

    # Debian package
    if suffix == ".deb":
        return _verify_dpkg(path)

    # RPM package
    if suffix == ".rpm":
        return _verify_rpm(path)

    # Check if ELF belongs to a distro package (implies signed provenance)
    if _is_elf(path):
        return _verify_elf_package_membership(path)

    # PE files on Linux (scanning Windows malware on a Linux host)
    if suffix in (".exe", ".dll", ".sys", ".scr"):
        return _verify_pe_with_signify(path)

    return SignatureVerdict(
        is_signed=False, is_valid=False, is_trusted=False,
        is_vendor_trusted=False, error_code=0,
        error_description="No signature mechanism for this file type on Linux",
    )


def _is_elf(path: Path) -> bool:
    """Quick check: does the file start with the ELF magic bytes?"""
    try:
        with open(path, "rb") as f:
            return f.read(4) == b"\x7fELF"
    except Exception:
        return False


def _verify_dpkg(path: Path) -> SignatureVerdict:
    """Verify Debian package signature."""
    try:
        result = subprocess.run(
            ["dpkg-sig", "--verify", str(path)],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode == 0 and "GOODSIG" in result.stdout:
            return SignatureVerdict(
                is_signed=True, is_valid=True, is_trusted=True,
                is_vendor_trusted=True, error_code=0,
                error_description="Valid dpkg signature",
            )
        return SignatureVerdict(
            is_signed="NOSIG" not in result.stdout,
            is_valid=False, is_trusted=False,
            is_vendor_trusted=False, error_code=result.returncode,
            error_description=result.stdout.strip() or result.stderr.strip(),
        )
    except FileNotFoundError:
        return SignatureVerdict(
            is_signed=False, is_valid=False, is_trusted=False,
            is_vendor_trusted=False, error_code=-1,
            error_description="dpkg-sig not installed",
        )
    except Exception as exc:
        return SignatureVerdict(
            is_signed=False, is_valid=False, is_trusted=False,
            is_vendor_trusted=False, error_code=-1,
            error_description=str(exc),
        )


def _verify_rpm(path: Path) -> SignatureVerdict:
    """Verify RPM package signature."""
    try:
        result = subprocess.run(
            ["rpm", "--checksig", str(path)],
            capture_output=True, text=True, timeout=10,
        )
        stdout = result.stdout.lower()
        if result.returncode == 0 and ("pgp" in stdout or "gpg" in stdout):
            return SignatureVerdict(
                is_signed=True, is_valid=True, is_trusted=True,
                is_vendor_trusted=True, error_code=0,
                error_description="Valid RPM GPG signature",
            )
        return SignatureVerdict(
            is_signed=False, is_valid=False, is_trusted=False,
            is_vendor_trusted=False, error_code=result.returncode,
            error_description=result.stdout.strip(),
        )
    except FileNotFoundError:
        return SignatureVerdict(
            is_signed=False, is_valid=False, is_trusted=False,
            is_vendor_trusted=False, error_code=-1,
            error_description="rpm not installed",
        )
    except Exception as exc:
        return SignatureVerdict(
            is_signed=False, is_valid=False, is_trusted=False,
            is_vendor_trusted=False, error_code=-1,
            error_description=str(exc),
        )


def _verify_elf_package_membership(path: Path) -> SignatureVerdict:
    """Check if an ELF binary belongs to a distro package (implies signed provenance)."""
    # Try dpkg first (Debian/Ubuntu)
    for cmd in (["dpkg", "-S"], ["rpm", "-qf"]):
        try:
            result = subprocess.run(
                cmd + [str(path)],
                capture_output=True, text=True, timeout=5,
            )
            if result.returncode == 0 and result.stdout.strip():
                pkg = result.stdout.strip().split(":")[0] if ":" in result.stdout else result.stdout.strip()
                return SignatureVerdict(
                    is_signed=True, is_valid=True, is_trusted=True,
                    is_vendor_trusted=True, error_code=0,
                    error_description=f"Distro package: {pkg}",
                )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue
        except Exception:
            continue

    return SignatureVerdict(
        is_signed=False, is_valid=False, is_trusted=False,
        is_vendor_trusted=False, error_code=0,
        error_description="ELF binary not part of a known distro package",
    )


def _verify_pe_with_signify(path: Path) -> SignatureVerdict:
    """Verify Authenticode signature on a PE file using the signify library (cross-platform)."""
    try:
        from signify.authenticode import AuthenticodeSignedData
        from signify.fingerprinter import AuthenticodeFingerprinter

        with open(path, "rb") as f:
            fingerprinter = AuthenticodeFingerprinter(f)
            fingerprinter.add_authenticode_hashers()
            hashes = fingerprinter.hash()

        with open(path, "rb") as f:
            signed_data = AuthenticodeSignedData.from_envelope(f)

        if signed_data:
            return SignatureVerdict(
                is_signed=True, is_valid=True, is_trusted=False,
                is_vendor_trusted=False, error_code=0,
                error_description="Authenticode signature present (trust not verified on Linux)",
            )
    except ImportError:
        logger.debug("signify library not installed — skipping PE signature check")
    except Exception as exc:
        logger.debug("PE signature check via signify failed: %s", exc)

    return SignatureVerdict(
        is_signed=False, is_valid=False, is_trusted=False,
        is_vendor_trusted=False, error_code=0,
        error_description="No verifiable signature",
    )


# ---------------------------------------------------------------------------
# macOS — codesign --verify
# ---------------------------------------------------------------------------
def _verify_macos(path: Path) -> SignatureVerdict:
    """macOS code signature verification via ``codesign --verify``."""
    try:
        # --deep verifies nested code (frameworks, plugins)
        result = subprocess.run(
            ["codesign", "--verify", "--deep", "--strict", str(path)],
            capture_output=True, text=True, timeout=15,
        )
        if result.returncode == 0:
            # Check if it's Apple-signed
            info_result = subprocess.run(
                ["codesign", "-dvv", str(path)],
                capture_output=True, text=True, timeout=10,
            )
            stderr = info_result.stderr.lower()
            is_apple = "apple" in stderr or "software signing" in stderr
            authority = ""
            for line in info_result.stderr.splitlines():
                if line.startswith("Authority="):
                    authority = line.split("=", 1)[1]
                    break

            return SignatureVerdict(
                is_signed=True,
                is_valid=True,
                is_trusted=True,
                is_vendor_trusted=is_apple,
                error_code=0,
                error_description=f"Valid signature: {authority}" if authority else "Valid code signature",
            )

        # Signed but invalid
        stderr = result.stderr.strip()
        if "not signed" in stderr.lower():
            return SignatureVerdict(
                is_signed=False, is_valid=False, is_trusted=False,
                is_vendor_trusted=False, error_code=result.returncode,
                error_description="Not code signed",
            )

        return SignatureVerdict(
            is_signed=True, is_valid=False, is_trusted=False,
            is_vendor_trusted=False, error_code=result.returncode,
            error_description=stderr,
        )
    except FileNotFoundError:
        return SignatureVerdict(
            is_signed=False, is_valid=False, is_trusted=False,
            is_vendor_trusted=False, error_code=-1,
            error_description="codesign command not found",
        )
    except Exception as exc:
        return SignatureVerdict(
            is_signed=False, is_valid=False, is_trusted=False,
            is_vendor_trusted=False, error_code=-1,
            error_description=str(exc),
        )
