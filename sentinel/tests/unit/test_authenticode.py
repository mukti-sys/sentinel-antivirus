"""Unit tests for Authenticode signature verification and HashBlocklist defense-in-depth."""
import sys
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from sentinel.engine.authenticode import verify_pe_signature, SignatureResult
from sentinel.kernel.bridge import HashBlocklist, KernelBridge


class TestAuthenticodeVerification:
    def test_python_executable_has_signature(self):
        """Python executable on Windows is signed."""
        py_exe = sys.executable
        res = verify_pe_signature(py_exe)
        assert isinstance(res, SignatureResult)
        # On standard Windows python installations, python.exe is signed
        if res.is_signed:
            assert res.is_valid is True

    def test_unsigned_temp_file(self, tmp_path):
        """An unsigned scratch file returns is_signed=False, is_valid=False."""
        scratch = tmp_path / "fake.exe"
        scratch.write_bytes(b"MZ\x90\x00\x03\x00\x00\x00NOT_A_REAL_PE")
        res = verify_pe_signature(scratch)
        assert res.is_signed is False
        assert res.is_valid is False

    def test_nonexistent_file(self):
        """Non-existent file gracefully returns is_signed=False."""
        res = verify_pe_signature(r"C:\nonexistent_path_xyz\random.dll")
        assert res.is_signed is False
        assert res.is_valid is False


class TestHashBlocklist:
    def test_compute_sha256(self, tmp_path):
        data = b"MaliciousContent12345"
        f = tmp_path / "sample.bin"
        f.write_bytes(data)

        # From bytes
        sha_bytes = HashBlocklist.compute_sha256(data)
        assert len(sha_bytes) == 64

        # From file
        sha_file = HashBlocklist.compute_sha256(str(f))
        assert sha_bytes == sha_file

    def test_add_and_query_hash(self, tmp_path):
        bl = HashBlocklist()
        sha = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

        bl.add_hash(sha, reason="test_threat", metadata={"family": "WannaCry"})
        blocked, info = bl.is_blocked(sha)
        assert blocked is True
        assert info["reason"] == "test_threat"
        assert info["metadata"]["family"] == "WannaCry"

        # Case insensitive query
        blocked_upper, _ = bl.is_blocked(sha.upper())
        assert blocked_upper is True

        # Non-blocked hash
        clean_sha = "0000000000000000000000000000000000000000000000000000000000000000"
        blocked_clean, _ = bl.is_blocked(clean_sha)
        assert blocked_clean is False

    def test_add_by_file_path(self, tmp_path):
        bl = HashBlocklist()
        sample = tmp_path / "evil.exe"
        sample.write_bytes(b"MalwarePayloadBytes")

        sha = bl.add_hash(str(sample), reason="payload_detected")
        assert sha is not None
        assert len(sha) == 64

        # Check by path
        blocked, info = bl.is_blocked(str(sample))
        assert blocked is True
        assert info["hash"] == sha

        # Remove hash
        assert bl.remove_hash(str(sample)) is True
        blocked_after, _ = bl.is_blocked(str(sample))
        assert blocked_after is False

    def test_bridge_integration(self, tmp_path):
        bridge = KernelBridge()
        test_file = tmp_path / "ransomware.exe"
        test_file.write_bytes(b"LockBitSimulatedBytes")

        # Add block via bridge
        sha = bridge.add_hash_block(str(test_file), reason="LockBit")
        assert sha is not None

        # Verify dual-layer check detects it via hash_blocklist
        blocked, reason = bridge.check_file_blocked(str(test_file))
        assert blocked is True
        assert "hash_blocklist" in reason

        # Remove via bridge
        assert bridge.remove_hash_block(str(test_file)) is True
        blocked_after, _ = bridge.check_file_blocked(str(test_file))
        assert blocked_after is False

    def test_safety_check_prevents_microsoft_blocking(self):
        bridge = KernelBridge()
        # Mock verify_pe_signature to simulate explorer.exe or svchost.exe
        mock_sig = SignatureResult(
            is_signed=True,
            is_valid=True,
            is_trusted=True,
            is_microsoft=True,
            error_code=0,
            error_description="The operation completed successfully.",
        )
        with patch("sentinel.engine.authenticode.verify_pe_signature", return_value=mock_sig):
            # Attempt to block without force should fail
            ok = bridge.add_block(r"C:\Windows\explorer.exe", force=False)
            assert ok is False

            # With force=True, it allows it through (to bridge connect status)
            # Since bridge is not connected, it returns False for driver send, but bypassed the refusal
            ok_force = bridge.add_block(r"C:\Windows\explorer.exe", force=True)
            # Not connected to driver, so returns False from driver send, but did not abort at safety check
