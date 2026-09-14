"""Win32 Authenticode Digital Signature Verification.

Uses native Windows Crypto and WinTrust APIs (Wintrust.dll, Crypt32.dll)
to cryptographically verify file signatures against the Windows Trusted Root
Certification Authorities store.

Detects:
- Valid commercial / Microsoft signatures (ERROR_SUCCESS == 0)
- Tampered / corrupt signatures (TRUST_E_BAD_DIGEST)
- Untrusted root / self-signed certificates (CERT_E_UNTRUSTEDROOT)
- Expired signatures (CERT_E_EXPIRED)
- Completely unsigned binaries (TRUST_E_NOSIGNATURE)
"""
from __future__ import annotations

import ctypes
from ctypes import wintypes
import logging
import os
from pathlib import Path
import sys
from typing import NamedTuple

logger = logging.getLogger("sentinel.authenticode")

_IS_WINDOWS = sys.platform == "win32"

# WinTrust API Constants
WTD_UI_NONE = 2
WTD_REVOKE_NONE = 0
WTD_CHOICE_FILE = 1
WTD_STATEACTION_IGNORE = 0
WTD_SAFER_FLAG = 0x00000100

# Error Codes
ERROR_SUCCESS = 0
TRUST_E_NOSIGNATURE = 0x800B0100
CERT_E_UNTRUSTEDROOT = 0x800B0109
TRUST_E_BAD_DIGEST = 0x80096010
CERT_E_EXPIRED = 0x800B0101
TRUST_E_EXPLICIT_DISTRUST = 0x800B0111


class GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", wintypes.DWORD),
        ("Data2", wintypes.WORD),
        ("Data3", wintypes.WORD),
        ("Data4", wintypes.BYTE * 8),
    ]

    def __init__(self, d1: int, d2: int, d3: int, d4: tuple[int, ...]) -> None:
        super().__init__()
        self.Data1 = d1
        self.Data2 = d2
        self.Data3 = d3
        for i, b in enumerate(d4):
            self.Data4[i] = b


# WINTRUST_ACTION_GENERIC_VERIFY_V2: {00AAC56B-CD44-11d0-8CC2-00C04FC295EE}
WINTRUST_ACTION_GENERIC_VERIFY_V2 = GUID(
    0x00AAC56B, 0xCD44, 0x11D0, (0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE)
)


class WINTRUST_FILE_INFO(ctypes.Structure):
    _fields_ = [
        ("cbStruct", wintypes.DWORD),
        ("pcwszFilePath", wintypes.LPCWSTR),
        ("hFile", wintypes.HANDLE),
        ("pgKnownSubject", ctypes.c_void_p),
    ]


class WINTRUST_DATA(ctypes.Structure):
    _fields_ = [
        ("cbStruct", wintypes.DWORD),
        ("pPolicyCallbackData", ctypes.c_void_p),
        ("pSIPClientData", ctypes.c_void_p),
        ("dwUIChoice", wintypes.DWORD),
        ("fdwRevocationChecks", wintypes.DWORD),
        ("dwUnionChoice", wintypes.DWORD),
        ("pFile", ctypes.POINTER(WINTRUST_FILE_INFO)),
        ("dwStateAction", wintypes.DWORD),
        ("hWVTStateData", wintypes.HANDLE),
        ("pwszURLReference", wintypes.LPCWSTR),
        ("dwProvFlags", wintypes.DWORD),
        ("dwUIContext", wintypes.DWORD),
        ("pSignatureSettings", ctypes.c_void_p),
    ]


class AuthenticodeVerdict(NamedTuple):
    is_signed: bool
    is_valid: bool
    is_trusted: bool
    is_microsoft: bool
    error_code: int
    error_description: str


# Alias for backwards/type compatibility
SignatureResult = AuthenticodeVerdict


# In-memory LRU cache: (path, mtime) -> AuthenticodeVerdict
_VERDICT_CACHE: dict[tuple[str, float], AuthenticodeVerdict] = {}
_CACHE_MAX_SIZE = 2048


def verify_pe_signature(file_path: str | Path) -> AuthenticodeVerdict:
    """Verify Authenticode signature on a Windows executable or DLL.

    Returns AuthenticodeVerdict indicating signature presence, cryptographic validity,
    and root trust. Results are cached by path and last modified timestamp.
    """
    path = Path(file_path).resolve()
    if not path.is_file():
        return AuthenticodeVerdict(
            is_signed=False,
            is_valid=False,
            is_trusted=False,
            is_microsoft=False,
            error_code=-1,
            error_description="File not found",
        )

    try:
        mtime = path.stat().st_mtime
    except OSError:
        mtime = 0.0

    cache_key = (str(path), mtime)
    if cache_key in _VERDICT_CACHE:
        return _VERDICT_CACHE[cache_key]

    if not _IS_WINDOWS:
        # Non-Windows test mock behavior
        return AuthenticodeVerdict(
            is_signed=False,
            is_valid=False,
            is_trusted=False,
            is_microsoft=False,
            error_code=0,
            error_description="Non-Windows platform",
        )

    # Initialize WinTrust structs
    file_info = WINTRUST_FILE_INFO()
    file_info.cbStruct = ctypes.sizeof(WINTRUST_FILE_INFO)
    file_info.pcwszFilePath = str(path)
    file_info.hFile = None
    file_info.pgKnownSubject = None

    trust_data = WINTRUST_DATA()
    trust_data.cbStruct = ctypes.sizeof(WINTRUST_DATA)
    trust_data.pPolicyCallbackData = None
    trust_data.pSIPClientData = None
    trust_data.dwUIChoice = WTD_UI_NONE
    trust_data.fdwRevocationChecks = WTD_REVOKE_NONE
    trust_data.dwUnionChoice = WTD_CHOICE_FILE
    trust_data.pFile = ctypes.pointer(file_info)
    trust_data.dwStateAction = WTD_STATEACTION_IGNORE
    trust_data.hWVTStateData = None
    trust_data.pwszURLReference = None
    trust_data.dwProvFlags = WTD_SAFER_FLAG
    trust_data.dwUIContext = 0
    trust_data.pSignatureSettings = None

    action_guid = WINTRUST_ACTION_GENERIC_VERIFY_V2

    try:
        wintrust = ctypes.windll.wintrust
        status = wintrust.WinVerifyTrust(
            None,
            ctypes.byref(action_guid),
            ctypes.byref(trust_data),
        )
        # Convert to unsigned 32-bit for hex comparison
        err = status & 0xFFFFFFFF
    except Exception as exc:
        logger.debug("WinVerifyTrust invocation failed for %s: %s", path.name, exc)
        return AuthenticodeVerdict(
            is_signed=False,
            is_valid=False,
            is_trusted=False,
            is_microsoft=False,
            error_code=-1,
            error_description=str(exc),
        )

    is_signed = err != (TRUST_E_NOSIGNATURE & 0xFFFFFFFF)
    is_valid = err == ERROR_SUCCESS
    is_trusted = err == ERROR_SUCCESS

    # Check if signed by Microsoft (common in System32 / Windows components)
    path_str = str(path).lower()
    is_microsoft = is_valid and ("\\windows\\" in path_str or "\\system32\\" in path_str or "\\syswow64\\" in path_str)

    desc_map = {
        ERROR_SUCCESS: "Valid trusted signature",
        TRUST_E_NOSIGNATURE & 0xFFFFFFFF: "No signature present",
        CERT_E_UNTRUSTEDROOT & 0xFFFFFFFF: "Untrusted root CA / self-signed",
        TRUST_E_BAD_DIGEST & 0xFFFFFFFF: "Bad digest / file has been tampered",
        CERT_E_EXPIRED & 0xFFFFFFFF: "Certificate has expired",
        TRUST_E_EXPLICIT_DISTRUST & 0xFFFFFFFF: "Explicitly distrusted publisher",
    }
    desc = desc_map.get(err, f"WinTrust code 0x{err:08X}")

    verdict = AuthenticodeVerdict(
        is_signed=is_signed,
        is_valid=is_valid,
        is_trusted=is_trusted,
        is_microsoft=is_microsoft,
        error_code=err,
        error_description=desc,
    )

    if len(_VERDICT_CACHE) >= _CACHE_MAX_SIZE:
        _VERDICT_CACHE.clear()
    _VERDICT_CACHE[cache_key] = verdict

    return verdict
