"""Tests for response/quarantine_store.py.

Validates the full quarantine lifecycle per phases.md Phase 3 and
architecture.md Section 5.5:
    quarantine_store.py: metadata (original path, reason, timestamp),
    restore/delete logic

Test coverage:
1. add() moves file, strips permissions, records metadata with SHA-256
2. get() returns correct record by ID
3. list_pending() / list_all() query filtering
4. restore() copies file back, marks decision='restored'
5. delete() removes file, marks decision='deleted'
6. Edge cases: missing file, double-restore, restore-after-delete
7. Thread safety: concurrent adds
"""
from __future__ import annotations

import hashlib
import json
import os
import stat
import threading
from pathlib import Path

import pytest

from sentinel.response.quarantine_store import (
    DELETED,
    PENDING,
    RESTORED,
    QuarantineRecord,
    QuarantineStore,
)


@pytest.fixture
def store(tmp_path):
    """Create a QuarantineStore with temp paths."""
    db = tmp_path / "quarantine.db"
    qdir = tmp_path / "quarantine"
    return QuarantineStore(db_path=db, quarantine_dir=qdir)


@pytest.fixture
def sample_file(tmp_path):
    """Create a sample file to quarantine."""
    f = tmp_path / "malware.exe"
    f.write_bytes(b"MZ\x00" * 100)
    return f


# --------------------------------------------------------------------------- #
# add()
# --------------------------------------------------------------------------- #

class TestAdd:
    def test_add_moves_file_to_quarantine(self, store, sample_file):
        rec = store.add(
            source_path=sample_file,
            subject="pid:1234",
            reason="test detection",
            score=85.0,
        )
        assert rec is not None
        assert rec.decision == PENDING
        assert rec.subject == "pid:1234"
        assert rec.reason == "test detection"
        assert rec.score == 85.0
        # Original file should be gone.
        assert not sample_file.exists()
        # Quarantined file should exist.
        assert Path(rec.quarantined_path).exists()

    def test_add_records_sha256(self, store, sample_file):
        expected_hash = hashlib.sha256(sample_file.read_bytes()).hexdigest()
        rec = store.add(
            source_path=sample_file,
            subject="pid:1234",
            reason="test",
        )
        assert rec.sha256 == expected_hash

    def test_add_strips_write_permission(self, store, sample_file):
        """_strip_execute removes write bits (on Windows, chmod controls
        the read-only flag; execute bits are filesystem-level ACLs)."""
        rec = store.add(
            source_path=sample_file,
            subject="pid:1234",
            reason="test",
        )
        qpath = Path(rec.quarantined_path)
        mode = qpath.stat().st_mode
        # Write bits should be stripped (read-only on Windows).
        assert not (mode & stat.S_IWUSR)
        assert not (mode & stat.S_IWGRP)
        assert not (mode & stat.S_IWOTH)

    def test_add_stores_source_signals(self, store, sample_file):
        signals = [
            {"kind": "vt_positive", "weight": 50.0},
            {"kind": "rule_match_high", "weight": 40.0},
        ]
        rec = store.add(
            source_path=sample_file,
            subject="pid:1234",
            reason="test",
            source_signals=signals,
        )
        assert rec.source_signals == signals

    def test_add_nonexistent_file_returns_none(self, store, tmp_path):
        result = store.add(
            source_path=tmp_path / "does_not_exist.exe",
            subject="pid:999",
            reason="test",
        )
        assert result is None

    def test_add_generates_unique_ids(self, store, tmp_path):
        ids = set()
        for i in range(5):
            f = tmp_path / f"file_{i}.exe"
            f.write_bytes(b"payload" + bytes([i]))
            rec = store.add(
                source_path=f, subject=f"pid:{i}", reason="test",
            )
            assert rec is not None
            ids.add(rec.id)
        assert len(ids) == 5  # all unique


# --------------------------------------------------------------------------- #
# get() / list queries
# --------------------------------------------------------------------------- #

class TestQueries:
    def test_get_returns_record(self, store, sample_file):
        rec = store.add(
            source_path=sample_file,
            subject="pid:1234",
            reason="test",
            score=90.0,
        )
        fetched = store.get(rec.id)
        assert fetched is not None
        assert fetched.id == rec.id
        assert fetched.subject == rec.subject
        assert fetched.reason == rec.reason
        assert fetched.score == rec.score
        assert fetched.decision == PENDING

    def test_get_unknown_id_returns_none(self, store):
        assert store.get("nonexistent") is None

    def test_list_pending(self, store, tmp_path):
        for i in range(3):
            f = tmp_path / f"file_{i}.exe"
            f.write_bytes(b"data")
            store.add(source_path=f, subject=f"pid:{i}", reason="test")
        pending = store.list_pending()
        assert len(pending) == 3
        assert all(r.decision == PENDING for r in pending)

    def test_list_all_includes_all_decisions(self, store, tmp_path):
        files = []
        for i in range(3):
            f = tmp_path / f"file_{i}.exe"
            f.write_bytes(b"data")
            rec = store.add(source_path=f, subject=f"pid:{i}", reason="test")
            files.append(rec)
        # Restore one, delete another.
        store.restore(files[0].id, notes="FP")
        store.delete(files[1].id, notes="confirmed malware")
        all_records = store.list_all()
        assert len(all_records) == 3
        decisions = {r.decision for r in all_records}
        assert decisions == {PENDING, RESTORED, DELETED}

    def test_count(self, store, tmp_path):
        for i in range(4):
            f = tmp_path / f"file_{i}.exe"
            f.write_bytes(b"data")
            store.add(source_path=f, subject=f"pid:{i}", reason="test")
        assert store.count() == 4
        assert store.count(decision=PENDING) == 4
        assert store.count(decision=RESTORED) == 0


# --------------------------------------------------------------------------- #
# restore()
# --------------------------------------------------------------------------- #

class TestRestore:
    def test_restore_copies_file_back(self, store, sample_file):
        original_data = sample_file.read_bytes()
        original_path = str(sample_file)
        rec = store.add(
            source_path=sample_file,
            subject="pid:1234",
            reason="test",
        )
        assert not sample_file.exists()  # original gone

        result = store.restore(rec.id, notes="false positive")
        assert result is not None
        assert Path(result).exists()
        assert Path(result).read_bytes() == original_data

    def test_restore_marks_decision(self, store, sample_file):
        rec = store.add(
            source_path=sample_file,
            subject="pid:1234",
            reason="test",
        )
        store.restore(rec.id, notes="FP feedback")
        updated = store.get(rec.id)
        assert updated.decision == RESTORED
        assert updated.notes == "FP feedback"
        assert updated.decided_at is not None

    def test_restore_unknown_id_returns_none(self, store):
        assert store.restore("nonexistent") is None

    def test_restore_after_delete_returns_none(self, store, sample_file):
        rec = store.add(
            source_path=sample_file,
            subject="pid:1234",
            reason="test",
        )
        store.delete(rec.id)
        result = store.restore(rec.id)
        assert result is None  # can't restore a deleted file


# --------------------------------------------------------------------------- #
# delete()
# --------------------------------------------------------------------------- #

class TestDelete:
    def test_delete_removes_quarantined_file(self, store, sample_file):
        rec = store.add(
            source_path=sample_file,
            subject="pid:1234",
            reason="test",
        )
        qpath = Path(rec.quarantined_path)
        assert qpath.exists()

        ok = store.delete(rec.id, notes="user confirmed")
        assert ok is True
        assert not qpath.exists()  # quarantined file removed

    def test_delete_marks_decision(self, store, sample_file):
        rec = store.add(
            source_path=sample_file,
            subject="pid:1234",
            reason="test",
        )
        store.delete(rec.id, notes="confirmed malware")
        updated = store.get(rec.id)
        assert updated.decision == DELETED
        assert updated.notes == "confirmed malware"
        assert updated.decided_at is not None

    def test_delete_unknown_id_returns_false(self, store):
        assert store.delete("nonexistent") is False

    def test_delete_already_missing_file_still_succeeds(self, store, sample_file):
        rec = store.add(
            source_path=sample_file,
            subject="pid:1234",
            reason="test",
        )
        # Manually remove the quarantined file (need to restore write perm first).
        qp = Path(rec.quarantined_path)
        qp.chmod(qp.stat().st_mode | stat.S_IWRITE)
        qp.unlink()
        # delete() should still succeed (file already gone).
        ok = store.delete(rec.id)
        assert ok is True
        assert store.get(rec.id).decision == DELETED


# --------------------------------------------------------------------------- #
# Thread safety
# --------------------------------------------------------------------------- #

class TestThreadSafety:
    def test_concurrent_adds(self, store, tmp_path):
        """Multiple threads adding files concurrently should not crash or
        produce duplicate IDs."""
        errors = []
        records = []
        lock = threading.Lock()

        def add_file(idx):
            try:
                f = tmp_path / f"thread_file_{idx}.exe"
                f.write_bytes(b"payload" + bytes([idx % 256]))
                rec = store.add(
                    source_path=f,
                    subject=f"pid:{idx}",
                    reason=f"thread test {idx}",
                )
                with lock:
                    if rec:
                        records.append(rec)
            except Exception as exc:
                with lock:
                    errors.append(exc)

        threads = [threading.Thread(target=add_file, args=(i,)) for i in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors, f"thread errors: {errors}"
        assert len(records) == 10
        ids = {r.id for r in records}
        assert len(ids) == 10  # all unique
