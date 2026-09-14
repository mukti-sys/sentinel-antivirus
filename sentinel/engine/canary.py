"""Ransomware Canary Deception Engine (Honeypot Traps).

Deploys sacrificial canary documents in strategic user-space directories
(Desktop, Documents, Downloads, user profile) using high-priority alphabetical
sort prefixes (e.g. '!00_financial_statement.docx').

Ransomware enumerating files alphabetically or depth-first encounters and
attempts to encrypt or rename the canary BEFORE user documents can be reached.
The file system sensor intercepts this write/rename, tripping an immediate
'canary_tripped' alert (score 85.0 >= threshold 80.0) that freezes the attacker PID
via NtSuspendProcess and blocks its hash in the kernel minifilter.

Camouflage:
Canary files are marked with Windows FILE_ATTRIBUTE_HIDDEN (0x02) and
FILE_ATTRIBUTE_NOT_CONTENT_INDEXED (0x2000), keeping user directories visually
clean while remaining fully visible to filesystem traversal APIs used by ransomware.
"""
from __future__ import annotations

import ctypes
from ctypes import wintypes
import hashlib
import logging
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger("sentinel.canary")

# Windows File Attribute Constants
FILE_ATTRIBUTE_HIDDEN = 0x00000002
FILE_ATTRIBUTE_NOT_CONTENT_INDEXED = 0x00002000
FILE_ATTRIBUTE_NORMAL = 0x00000080

_SetFileAttributesW = None
if sys.platform == "win32":
    try:
        _SetFileAttributesW = ctypes.windll.kernel32.SetFileAttributesW
        _SetFileAttributesW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD]
        _SetFileAttributesW.restype = wintypes.BOOL
    except Exception as exc:
        logger.debug("Failed binding SetFileAttributesW: %s", exc)


@dataclass(frozen=True)
class CanaryTemplate:
    filename: str
    extension: str
    sample_content: bytes


# Authentic-looking document templates with genuine file headers
CANARY_TEMPLATES: list[CanaryTemplate] = [
    CanaryTemplate(
        filename="!00_financial_statement.docx",
        extension=".docx",
        sample_content=(
            b"PK\x03\x04\x14\x00\x06\x00\x08\x00\x00\x00!\x00\x01\x02\x03\x04\x00\x00\x00\x00"
            b"[Content_Types].xml<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n"
            b"<Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\">\n"
            b"<Default Extension=\"xml\" ContentType=\"application/xml\"/>\n"
            b"<Override PartName=\"/word/document.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml\"/>\n"
            b"</Types>\n<!-- Sentinel Canary Document Vault 2026 -->"
        ),
    ),
    CanaryTemplate(
        filename="!00_credentials_vault.xlsx",
        extension=".xlsx",
        sample_content=(
            b"PK\x03\x04\x14\x00\x06\x00\x08\x00\x00\x00!\x00\x05\x06\x07\x08\x00\x00\x00\x00"
            b"[Content_Types].xml<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n"
            b"<Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\">\n"
            b"<Default Extension=\"xml\" ContentType=\"application/xml\"/>\n"
            b"<Override PartName=\"/xl/workbook.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml\"/>\n"
            b"</Types>\n<!-- Sentinel Financial Record Trap -->"
        ),
    ),
    CanaryTemplate(
        filename="!00_cloud_backup_keys.pdf",
        extension=".pdf",
        sample_content=(
            b"%PDF-1.5\n%\xe2\xe3\xcf\xd3\n"
            b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
            b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n"
            b"3 0 obj\n<< /Type /Page /Parent 2 0 R /Resources <<>> /MediaBox [0 0 612 792] >>\nendobj\n"
            b"xref\n0 4\n0000000000 65535 f \n0000000015 00000 n \n0000000068 00000 n \n0000000125 00000 n \n"
            b"trailer\n<< /Size 4 /Root 1 0 R >>\nstartxref\n200\n%%EOF\n"
        ),
    ),
]


@dataclass
class CanaryTrap:
    path: Path
    template: CanaryTemplate
    original_sha256: str
    original_size: int
    is_armed: bool = True


def write_canary_content(path: Path, data: bytes, set_hidden: bool = True) -> None:
    """Safely write bytes to a canary file, managing Windows file attributes."""
    if _SetFileAttributesW is not None and path.exists():
        try:
            _SetFileAttributesW(str(path), FILE_ATTRIBUTE_NORMAL)
        except Exception:
            pass
    path.write_bytes(data)
    if set_hidden and _SetFileAttributesW is not None:
        try:
            _SetFileAttributesW(str(path), FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_NOT_CONTENT_INDEXED)
        except Exception:
            pass


class CanaryManager:
    """Manages creation, camouflage, inspection, and restoration of canary traps."""

    def __init__(self, target_directories: Optional[list[Path]] = None) -> None:
        self.target_directories: list[Path] = target_directories or self._default_directories()
        self._canaries: dict[str, CanaryTrap] = {}  # normalized lowercase path -> CanaryTrap
        self._armed_count = 0

    @staticmethod
    def _default_directories() -> list[Path]:
        """Resolve standard user directories for honeypot deployment."""
        dirs: list[Path] = []
        user_home = Path.home()

        candidates = [
            user_home / "Documents",
            user_home / "Desktop",
            user_home / "Downloads",
            user_home / "Pictures",
        ]
        for c in candidates:
            if c.is_dir():
                dirs.append(c)

        # Fallback if in service or minimal environment
        if not dirs:
            dirs.append(user_home)

        return dirs

    @staticmethod
    def compute_sha256(data: bytes) -> str:
        return hashlib.sha256(data).hexdigest().lower()

    def _set_hidden_attributes(self, path: Path) -> bool:
        """Apply Win32 HIDDEN and NOT_CONTENT_INDEXED attributes."""
        if _SetFileAttributesW is not None and path.exists():
            try:
                flags = FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_NOT_CONTENT_INDEXED
                success = _SetFileAttributesW(str(path), flags)
                return bool(success)
            except Exception as exc:
                logger.debug("Failed setting file attributes on %s: %s", path, exc)
        return False

    def arm_traps(self) -> int:
        """Deploy and arm canary traps across all target directories."""
        self._canaries.clear()
        armed = 0

        for directory in self.target_directories:
            if not directory.exists():
                try:
                    directory.mkdir(parents=True, exist_ok=True)
                except Exception as exc:
                    logger.debug("Could not create canary target directory %s: %s", directory, exc)
                    continue

            for tmpl in CANARY_TEMPLATES:
                file_path = directory / tmpl.filename
                try:
                    content = tmpl.sample_content
                    write_canary_content(file_path, content, set_hidden=True)

                    sha = self.compute_sha256(content)
                    trap = CanaryTrap(
                        path=file_path.resolve(),
                        template=tmpl,
                        original_sha256=sha,
                        original_size=len(content),
                        is_armed=True,
                    )
                    norm_path = str(file_path.resolve()).lower()
                    self._canaries[norm_path] = trap
                    armed += 1
                except Exception as exc:
                    logger.warning("Failed arming canary %s: %s", file_path, exc)

        self._armed_count = armed
        logger.info("CanaryManager: armed %d traps across %d directories", armed, len(self.target_directories))
        return armed

    @property
    def active_canaries(self) -> dict[str, CanaryTrap]:
        """Return the dictionary of active canary traps."""
        return self._canaries

    def verify_all_canaries(self) -> list[tuple[CanaryTrap, str]]:
        """Verify integrity of all registered canaries. Returns tampered list."""
        tampered_list = []
        for trap in self._canaries.values():
            tampered, reason = self.check_tampering(trap.path)
            if tampered:
                tampered_list.append((trap, reason))
        return tampered_list

    def is_canary(self, path_str: str | Path) -> bool:
        """Fast O(1) check if a given file path is a registered canary honeypot."""
        if not path_str:
            return False
        try:
            norm = str(Path(path_str).resolve()).lower()
            return norm in self._canaries
        except Exception:
            return False

    def check_tampering(self, path_str: str | Path) -> tuple[bool, str]:
        """Inspect a file path to determine if it is a tripped canary.

        Returns (is_tampered, reason_description).
        """
        if not path_str:
            return False, "clean"

        try:
            norm = str(Path(path_str).resolve()).lower()
        except Exception:
            return False, "clean"

        trap = self._canaries.get(norm)
        if trap is None:
            # Check filename heuristic in case of renamed canary in same folder
            p = Path(path_str)
            if p.name.startswith("!00_") and any(p.name.endswith(t.extension) for t in CANARY_TEMPLATES):
                return True, f"honeypot_pattern_match:{p.name}"
            return False, "clean"

        if not trap.path.exists():
            return True, f"canary_deleted:{trap.path.name}"

        try:
            current_data = trap.path.read_bytes()
            current_sha = self.compute_sha256(current_data)

            if current_sha != trap.original_sha256:
                return True, f"canary_modified_content:{trap.path.name}"

            if len(current_data) != trap.original_size:
                return True, f"canary_size_tampered:{trap.path.name}"

        except Exception as exc:
            return True, f"canary_access_denied_or_locked:{trap.path.name}:{exc}"

        return False, "clean"

    def repair_canaries(self) -> int:
        """Restore any modified, corrupted, or deleted canaries back to fresh state."""
        repaired = 0
        for norm_path, trap in list(self._canaries.items()):
            tampered, _ = self.check_tampering(trap.path)
            if tampered:
                try:
                    content = trap.template.sample_content
                    write_canary_content(trap.path, content, set_hidden=True)
                    sha = self.compute_sha256(content)
                    self._canaries[norm_path] = CanaryTrap(
                        path=trap.path,
                        template=trap.template,
                        original_sha256=sha,
                        original_size=len(content),
                        is_armed=True,
                    )
                    repaired += 1
                except Exception as exc:
                    logger.error("Could not repair canary %s: %s", trap.path, exc)

        logger.info("CanaryManager: repaired %d canaries", repaired)
        return repaired

    def disarm_traps(self) -> None:
        """Clean up and delete all canary files (e.g. during uninstall or test teardown)."""
        for trap in self._canaries.values():
            try:
                if trap.path.exists():
                    # Reset normal attribute to allow clean deletion
                    if _SetFileAttributesW is not None:
                        _SetFileAttributesW(str(trap.path), FILE_ATTRIBUTE_NORMAL)
                    trap.path.unlink()
            except Exception as exc:
                logger.debug("Failed removing canary %s: %s", trap.path, exc)
        self._canaries.clear()
        self._armed_count = 0
        logger.info("CanaryManager: all traps disarmed and cleaned")

    def get_status(self) -> dict[str, Any]:
        """Return diagnostic and telemetry metadata."""
        return {
            "armed_traps": len(self._canaries),
            "target_directories": [str(d) for d in self.target_directories],
            "traps": [
                {
                    "path": str(t.path),
                    "template": t.template.filename,
                    "sha256": t.original_sha256,
                    "is_armed": t.is_armed,
                }
                for t in self._canaries.values()
            ],
        }
