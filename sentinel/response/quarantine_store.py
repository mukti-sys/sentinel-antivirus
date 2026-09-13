"""Quarantine store — metadata DB tracking original path, reason, timestamp;
supports restore or permanent delete (NFR-3: reversible until user confirms).

Implements architecture.md Section 5.5 (`response/quarantine_store.py`) and
phases.md Phase 3:
    quarantine_store.py: metadata (original path, reason, timestamp),
    restore/delete logic

Design (NFR-3 driven):
- Every quarantined file gets a row: original_path, quarantined_path, reason,
  score, timestamp, decision (pending | restored | deleted), notes.
- The file is moved to data/quarantine/ (isolated). The row is the source of
  truth for putting it back exactly where it came from (restore) or removing
  it permanently (confirm delete).
- Execute permission is stripped on the quarantined copy (architecture.md
  Section 5.5: "strip execute permission").
- SHA-256 hash is computed and stored for traceability.
- Source signals that led to the quarantine are stored as JSON for audit.
- Nothing is auto-deleted. `delete()` only runs on an explicit user decision
  (via tray_app), per PRD S5 + NFR-3.
- The store records the user's decision back (restore/delete + notes) — this
  is the "feeds decision back as training data" hook (phases.md Cross-Phase).

SQLite-backed (separate from events.db so quarantine survives event-log
churn). Thread-safe via a per-instance lock + check_same_thread=False.
"""
from __future__ import annotations

import hashlib
import json
import logging
import shutil
import sqlite3
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_DEFAULT_DIR = Path(__file__).resolve().parent.parent / "data"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS quarantine (
    id               TEXT PRIMARY KEY,
    subject          TEXT    NOT NULL,
    original_path    TEXT    NOT NULL,
    quarantined_path TEXT    NOT NULL,
    sha256           TEXT    NOT NULL DEFAULT '',
    reason           TEXT    NOT NULL,
    score            REAL    NOT NULL DEFAULT 0.0,
    timestamp        TEXT    NOT NULL,
    source_signals   TEXT    NOT NULL DEFAULT '[]',
    decision         TEXT    NOT NULL DEFAULT 'pending',
    notes            TEXT    NOT NULL DEFAULT '',
    decided_at       REAL
);
CREATE INDEX IF NOT EXISTS idx_quarantine_decision ON quarantine(decision);
"""

# Valid user decisions (NFR-3: reversible until 'deleted').
PENDING = "pending"
RESTORED = "restored"
DELETED = "deleted"


@dataclass(frozen=True)
class QuarantineRecord:
    """A single quarantined item, stored in the metadata DB."""

    id: str
    subject: str
    original_path: str
    quarantined_path: str
    reason: str
    score: float = 0.0
    timestamp: str = ""
    sha256: str = ""
    source_signals: list[dict[str, Any]] = field(default_factory=list)
    decision: str = PENDING
    notes: str = ""
    decided_at: float | None = None


class QuarantineStore:
    """Metadata DB + restore/delete logic for quarantined files.
    Thread-safe via a per-instance lock.
    """

    def __init__(
        self,
        db_path: str | Path | None = None,
        quarantine_dir: str | Path | None = None,
    ) -> None:
        self._db_path = Path(db_path) if db_path else (_DEFAULT_DIR / "quarantine.db")
        self._quarantine_dir = (
            Path(quarantine_dir) if quarantine_dir else (_DEFAULT_DIR / "quarantine")
        )
        self._quarantine_dir.mkdir(parents=True, exist_ok=True)
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(str(self._db_path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    @property
    def quarantine_dir(self) -> Path:
        return self._quarantine_dir

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # ------------------------------------------------------------------ #
    # Add (move file into isolation + record metadata)
    # ------------------------------------------------------------------ #

    @staticmethod
    def _sha256_of(path: Path) -> str:
        """Return hex SHA-256 of a file, or empty string on error."""
        try:
            return hashlib.sha256(path.read_bytes()).hexdigest()
        except (OSError, PermissionError):
            return ""

    @staticmethod
    def _strip_execute(path: Path) -> None:
        """Remove execute and write permissions from a quarantined file.

        On POSIX systems, removes execute and write permission bits.
        On Windows, marks read-only and applies an explicit deny-execute ACE
        via icacls (Deny execute to Everyone). Primary kernel pre-execution
        blocking is enforced by the SentinelFilter minifilter driver (Phase 4).
        """
        try:
            current = path.stat().st_mode
            path.chmod(current & ~0o111)  # remove POSIX execute bits
            path.chmod(path.stat().st_mode & ~0o222)  # remove write bits (read-only)
        except Exception:
            pass

        import sys
        if sys.platform == "win32":
            try:
                import subprocess
                subprocess.run(
                    ["icacls", str(path), "/deny", "*S-1-1-0:(X)"],
                    capture_output=True,
                    timeout=2.0,
                    check=False,
                )
            except Exception as exc:
                logger.debug("icacls deny execute failed: %s", exc)

    def add(
        self,
        source_path: str | Path,
        subject: str,
        reason: str,
        score: float = 0.0,
        source_signals: list[dict[str, Any]] | None = None,
    ) -> QuarantineRecord | None:
        """Move `source_path` into quarantine, strip execute/strip-write
        permissions, record metadata. Returns the record, or None on error
        (file not found, permission denied) — graceful degradation.

        The file is moved to ``quarantine_dir/<uuid>_<original_name>``.
        """
        src = Path(source_path)
        if not src.is_file():
            logger.warning("quarantine add: file not found %s", src)
            return None

        entry_id = uuid.uuid4().hex[:16]
        dest = self._quarantine_dir / f"{entry_id}_{src.name}"
        sha256 = self._sha256_of(src)

        try:
            # Copy first so a backup exists even if something fails mid-way.
            shutil.copy2(str(src), str(dest))
            self._strip_execute(dest)
            # Remove the original.
            src.unlink(missing_ok=True)
        except (OSError, PermissionError) as exc:
            logger.error("quarantine move failed for %s: %s", src, exc)
            if dest.exists():
                dest.unlink(missing_ok=True)
            return None

        ts = _utc_now()
        sigs_json = json.dumps(source_signals or [], default=str)

        with self._lock:
            try:
                self._conn.execute(
                    "INSERT INTO quarantine "
                    "(id, subject, original_path, quarantined_path, sha256, "
                    " reason, score, timestamp, source_signals) "
                    "VALUES (?,?,?,?,?,?,?,?,?)",
                    (entry_id, subject, str(src.resolve()), str(dest),
                     sha256, reason, score, ts, sigs_json),
                )
                self._conn.commit()
            except sqlite3.Error as exc:
                logger.error("quarantine DB insert failed: %s", exc)
                if dest.exists():
                    dest.unlink(missing_ok=True)
                return None

        logger.info("quarantined %s -> %s (reason: %s, score: %.1f)",
                     src, dest, reason, score)
        return QuarantineRecord(
            id=entry_id, subject=subject,
            original_path=str(src.resolve()), quarantined_path=str(dest),
            sha256=sha256, reason=reason, score=score, timestamp=ts,
            source_signals=source_signals or [], decision=PENDING,
        )

    # ------------------------------------------------------------------ #
    # Queries
    # ------------------------------------------------------------------ #

    def get(self, record_id: str) -> QuarantineRecord | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM quarantine WHERE id=?", (record_id,)
            ).fetchone()
        return self._to_record(row) if row else None

    def list_pending(self) -> list[QuarantineRecord]:
        return self._list(decision=PENDING)

    def list_all(self) -> list[QuarantineRecord]:
        return self._list(decision=None)

    def _list(self, decision: str | None) -> list[QuarantineRecord]:
        with self._lock:
            if decision is None:
                cur = self._conn.execute(
                    "SELECT * FROM quarantine ORDER BY timestamp DESC"
                )
            else:
                cur = self._conn.execute(
                    "SELECT * FROM quarantine WHERE decision=? ORDER BY timestamp DESC",
                    (decision,),
                )
            return [self._to_record(r) for r in cur.fetchall()]

    def count(self, decision: str | None = None) -> int:
        with self._lock:
            if decision is None:
                row = self._conn.execute(
                    "SELECT COUNT(*) FROM quarantine"
                ).fetchone()
            else:
                row = self._conn.execute(
                    "SELECT COUNT(*) FROM quarantine WHERE decision=?",
                    (decision,),
                ).fetchone()
            return row[0] if row else 0

    def _to_record(self, row: sqlite3.Row) -> QuarantineRecord:
        signals = []
        try:
            signals = json.loads(row["source_signals"]) if row["source_signals"] else []
        except (ValueError, TypeError):
            pass
        return QuarantineRecord(
            id=row["id"],
            subject=row["subject"],
            original_path=row["original_path"],
            quarantined_path=row["quarantined_path"],
            sha256=row["sha256"] or "",
            reason=row["reason"],
            score=row["score"],
            timestamp=row["timestamp"],
            source_signals=signals,
            decision=row["decision"],
            notes=row["notes"],
            decided_at=row["decided_at"],
        )

    # ------------------------------------------------------------------ #
    # Decisions: restore (reversible) / delete (permanent)
    # ------------------------------------------------------------------ #

    def restore(self, record_id: str, notes: str = "") -> str | None:
        """Put the quarantined file back at its original path.
        Returns the restored path, or None on error.
        Marks decision='restored' + logs the note (FP feedback)."""
        rec = self.get(record_id)
        if rec is None:
            logger.warning("restore: unknown record %s", record_id)
            return None
        if rec.decision == DELETED:
            logger.warning("restore: record %s already deleted", record_id)
            return None

        src = Path(rec.quarantined_path)
        dest = Path(rec.original_path)
        if not src.is_file():
            logger.warning("restore: quarantined file missing %s", src)
            return None

        try:
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(str(src), str(dest))
            # Restore normal permissions on the restored file
            try:
                import stat, sys
                dest.chmod(dest.stat().st_mode | stat.S_IWRITE | stat.S_IEXEC)
                if sys.platform == "win32":
                    import subprocess
                    subprocess.run(
                        ["icacls", str(dest), "/remove:d", "*S-1-1-0"],
                        capture_output=True,
                        timeout=2.0,
                        check=False,
                    )
            except Exception:
                pass
            # Leave the quarantined copy for audit; it will be removed on
            # delete() or can be pruned later.
        except (OSError, PermissionError) as exc:
            logger.error("restore failed for %s: %s", record_id, exc)
            return None

        self._decide(record_id, RESTORED, notes)
        logger.info("restored quarantined file to %s (FP feedback)", dest)
        return str(dest)

    def delete(self, record_id: str, notes: str = "") -> bool:
        """Permanently remove the quarantined file (user-confirmed).
        This is the destructive step — only called after explicit user
        confirmation (tray_app). NFR-3: reversible until this point.
        Returns True on success, False on error."""
        rec = self.get(record_id)
        if rec is None:
            logger.warning("delete: unknown record %s", record_id)
            return False

        qpath = Path(rec.quarantined_path)
        if qpath.exists():
            try:
                # _strip_execute makes the file read-only; restore write
                # permission before deleting (Windows requires it).
                import stat
                qpath.chmod(qpath.stat().st_mode | stat.S_IWRITE)
                qpath.unlink()
            except (OSError, PermissionError) as exc:
                logger.error("delete: could not remove %s: %s", qpath, exc)
                return False

        self._decide(record_id, DELETED, notes)
        logger.info("permanently deleted quarantined file %s (user confirmed)",
                    rec.original_path)
        return True

    def _decide(self, record_id: str, decision: str, notes: str) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE quarantine SET decision=?, notes=?, decided_at=? WHERE id=?",
                (decision, notes, time.time(), record_id),
            )
            self._conn.commit()


def _utc_now() -> str:
    """Return ISO-8601 UTC timestamp matching the Event schema format
    (engine/schema.py: "2026-07-16T10:22:31.000Z")."""
    dt = datetime.now(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"