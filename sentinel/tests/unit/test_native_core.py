"""Unit tests for Sentinel native Rust acceleration core and Python fallback."""

import os
import tempfile
from pathlib import Path
import pytest

from sentinel.engine import native_core
from sentinel.sensors.fs_sensor import shannon_entropy as py_shannon_entropy


class TestNativeCore:
    def test_native_library_available(self):
        """Native shared library should be loaded and report version 2.2.0."""
        assert native_core.is_native_available() is True
        assert native_core.get_native_version() == "2.2.0"

    def test_fast_sha256_matches_python_hashlib(self, tmp_path):
        """Streaming fast_sha256 must match Python hashlib exactly."""
        test_file = tmp_path / "sample.bin"
        content = b"Sentinel Antivirus High Performance Native Core 2026" * 1024
        test_file.write_bytes(content)

        native_hash = native_core.fast_sha256(test_file)
        import hashlib
        expected_hash = hashlib.sha256(content).hexdigest()

        assert native_hash == expected_hash

    def test_fast_dual_hash(self, tmp_path):
        """fast_dual_hash must return correct SHA-256 and MD5."""
        test_file = tmp_path / "dual.bin"
        content = b"Dual hash test data for Sentinel native engine"
        test_file.write_bytes(content)

        import hashlib
        exp_sha = hashlib.sha256(content).hexdigest()
        exp_md5 = hashlib.md5(content).hexdigest()

        res = native_core.fast_dual_hash(test_file)
        assert res is not None
        sha, md5 = res
        assert sha == exp_sha
        assert md5 == exp_md5

    def test_fast_entropy_parity_with_python(self):
        """Fast entropy must produce identical results to Python shannon_entropy."""
        # Test empty
        assert native_core.fast_entropy(b"") == 0.0

        # Test uniform
        assert native_core.fast_entropy(b"A" * 500) == 0.0

        # Test pseudo-random / diverse
        sample_bytes = bytes(range(256)) * 4
        native_ent = native_core.fast_entropy(sample_bytes)
        py_ent = py_shannon_entropy(sample_bytes)

        assert abs(native_ent - py_ent) < 1e-6
        assert abs(native_ent - 8.0) < 1e-6

    def test_fast_pe_triage_synthetic_pe(self):
        """Fast PE triage correctly parses DOS header, machine, and sections."""
        buf = bytearray(1024)
        buf[0] = ord('M')
        buf[1] = ord('Z')
        buf[0x3C] = 0x80  # e_lfanew = 128

        # PE\0\0
        buf[0x80] = ord('P')
        buf[0x81] = ord('E')
        buf[0x82] = 0
        buf[0x83] = 0

        # NumberOfSections = 3 at 0x86
        buf[0x86] = 3
        # SizeOfOptionalHeader = 0xE0 at 0x94
        buf[0x94] = 0xE0
        # OptionalHeader magic = PE32+ (0x20B) at 0x98
        buf[0x98] = 0x0B
        buf[0x99] = 0x02

        triage = native_core.fast_pe_triage(bytes(buf))
        assert triage is not None
        assert triage.is_pe is True
        assert triage.is_64bit is True
        assert triage.num_sections == 3

    def test_fast_pe_triage_non_pe(self):
        """Fast PE triage returns None for non-PE files."""
        assert native_core.fast_pe_triage(b"This is a text file") is None
        assert native_core.fast_pe_triage(b"MZ" + b"\x00" * 30) is None

    def test_fast_parallel_scan(self, tmp_path):
        """Parallel scan should discover and hash all files in directory."""
        dir1 = tmp_path / "sub1"
        dir2 = tmp_path / "sub2"
        dir1.mkdir()
        dir2.mkdir()

        f1 = dir1 / "file1.txt"
        f2 = dir2 / "file2.txt"
        f1.write_text("Hello from 1")
        f2.write_text("Hello from 2")

        discovered = {}
        def on_file(path, sha, fsize, is_pe, susp_packer):
            discovered[Path(path).name] = (sha, fsize)
            return True

        total = native_core.fast_parallel_scan(tmp_path, on_file)
        assert total >= 2
        assert "file1.txt" in discovered
        assert "file2.txt" in discovered
        assert len(discovered["file1.txt"][0]) == 64

    def test_graceful_fallback_when_native_lib_disabled(self, tmp_path, monkeypatch):
        """Verify 100% functional fallback when native library is None."""
        monkeypatch.setattr(native_core, "_NATIVE_LIB", None)
        assert native_core.is_native_available() is False

        test_file = tmp_path / "fallback.bin"
        test_file.write_bytes(b"Fallback test data")

        # fast_sha256 should still work seamlessly via pure-Python
        sha = native_core.fast_sha256(test_file)
        assert sha is not None
        assert len(sha) == 64

        # fast_entropy should still work via pure-Python
        ent = native_core.fast_entropy(b"ABCDEFG" * 20)
        assert ent > 0.0

        # fast_pe_triage should still work via pure-Python
        non_pe = native_core.fast_pe_triage(b"not a pe")
        assert non_pe is None
