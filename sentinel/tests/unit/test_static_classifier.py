"""Tests for engine/static_classifier.py — VT hash lookup + local PE-feature
fallback model (FR-5, architecture.md Section 5.3).

Core guarantees under test:
- VT malicious → vt_positive signal (weight 50, strong)
- VT clean → no signal (trusted)
- VT unknown + suspicious PE → vt_unknown_suspicious_pe signal (weight 15, weak)
- VT unknown + normal PE → no signal
- VT disabled (no API key) + suspicious PE → still emits PE signal (offline)
- Non-PE file → no PE signal (graceful)
- Deduplication: same hash not re-emitted
- Non-file-write events ignored
- File not found / permission error → graceful, no crash
- EICAR test harness analogue (plan.md Section 7)
"""
import hashlib
import math
import struct
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from sentinel.engine.schema import Event, utc_timestamp
from sentinel.engine.scoring import Signal
from sentinel.engine.static_classifier import (
    PEFeatureModel,
    PEFeatures,
    StaticClassifier,
    _file_entropy,
    _read_and_hash,
    extract_pe_features,
)
from sentinel.intel.virustotal_client import HashVerdict, VirusTotalClient


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _file_write_event(path: str) -> Event:
    return Event(
        timestamp=utc_timestamp(),
        source="fs",
        event_type="file_write",
        image_path=path,
    )


def _write_text_file(tmp_path: Path, name: str = "test.txt", content: str = "hello world") -> Path:
    f = tmp_path / name
    f.write_text(content)
    return f


def _write_minimal_pe(tmp_path: Path, name: str = "test.exe") -> Path:
    """Write a minimal valid PE file (just enough for pefile to parse)."""
    # Minimal DOS header + PE signature + COFF header + Optional header
    # This is a bare-minimum PE that pefile can open with fast_load=True.
    dos_header = bytearray(64)
    dos_header[0:2] = b"MZ"
    # e_lfanew: offset to PE signature (at byte 64)
    struct.pack_into("<I", dos_header, 60, 64)

    pe_sig = b"PE\x00\x00"

    # COFF header (20 bytes): Machine=0x14c (i386), 1 section
    coff = struct.pack("<HHIIIHH",
        0x14c,   # Machine (IMAGE_FILE_MACHINE_I386)
        1,       # NumberOfSections
        0,       # TimeDateStamp
        0,       # PointerToSymbolTable
        0,       # NumberOfSymbols
        0xE0,    # SizeOfOptionalHeader (standard 32-bit)
        0x0102,  # Characteristics (EXECUTABLE_IMAGE | 32BIT_MACHINE)
    )

    # Optional header (0xE0 = 224 bytes for PE32)
    opt = bytearray(0xE0)
    struct.pack_into("<H", opt, 0, 0x10b)  # Magic: PE32
    struct.pack_into("<I", opt, 16, 0x1000)  # AddressOfEntryPoint
    struct.pack_into("<I", opt, 28, 0x400000)  # ImageBase
    struct.pack_into("<I", opt, 32, 0x1000)  # SectionAlignment
    struct.pack_into("<I", opt, 36, 0x200)  # FileAlignment
    struct.pack_into("<I", opt, 56, 0x4000)  # SizeOfImage
    struct.pack_into("<I", opt, 60, 0x200)  # SizeOfHeaders
    struct.pack_into("<I", opt, 92, 16)  # NumberOfRvaAndSizes

    # Section header (40 bytes): .text section
    section = bytearray(40)
    section[0:6] = b".text\x00"
    struct.pack_into("<I", section, 8, 0x1000)  # VirtualSize
    struct.pack_into("<I", section, 12, 0x1000)  # VirtualAddress
    struct.pack_into("<I", section, 16, 0x200)  # SizeOfRawData
    struct.pack_into("<I", section, 20, 0x200)  # PointerToRawData
    struct.pack_into("<I", section, 36, 0x60000020)  # Characteristics (CODE|EXECUTE|READ)

    # Pad headers to SizeOfHeaders (0x200 = 512 bytes)
    header_data = dos_header + pe_sig + coff + bytes(opt) + bytes(section)
    header_data = header_data.ljust(0x200, b"\x00")

    # .text section data (0x200 bytes of NOPs as filler)
    text_data = b"\x90" * 0x200

    pe_data = header_data + text_data
    f = tmp_path / name
    f.write_bytes(pe_data)
    return f


def _mock_vt_client(verdict: str, positives: int = 0, total: int = 60) -> MagicMock:
    """Create a mock VT client that returns a fixed verdict."""
    client = MagicMock(spec=VirusTotalClient)
    client.lookup.return_value = HashVerdict(
        sha256="a" * 64,
        verdict=verdict,
        positives=positives,
        total=total,
        from_cache=False,
    )
    return client


# ---------------------------------------------------------------------------
# File entropy
# ---------------------------------------------------------------------------

class TestFileEntropy:
    def test_empty_data_zero_entropy(self):
        assert _file_entropy(b"") == 0.0

    def test_uniform_bytes_max_entropy(self):
        # 256 distinct bytes → entropy = 8.0 bits/byte (maximum)
        data = bytes(range(256)) * 100
        ent = _file_entropy(data)
        assert abs(ent - 8.0) < 0.01

    def test_single_byte_zero_entropy(self):
        assert _file_entropy(b"\x00" * 1000) == 0.0


# ---------------------------------------------------------------------------
# SHA-256 hashing
# ---------------------------------------------------------------------------

class TestReadAndHash:
    def test_correct_hash(self, tmp_path):
        f = _write_text_file(tmp_path)
        expected = hashlib.sha256(b"hello world").hexdigest()
        result = _read_and_hash(f)
        assert result is not None
        sha256, data = result
        assert sha256 == expected
        assert data == b"hello world"

    def test_nonexistent_file_returns_none(self, tmp_path):
        assert _read_and_hash(tmp_path / "nonexistent.exe") is None


# ---------------------------------------------------------------------------
# PE feature extraction
# ---------------------------------------------------------------------------

class TestPEFeatureExtraction:
    def test_non_pe_returns_none(self, tmp_path):
        f = _write_text_file(tmp_path, "readme.txt", "not a PE")
        assert extract_pe_features(f) is None

    def test_nonexistent_file_returns_none(self, tmp_path):
        assert extract_pe_features(tmp_path / "missing.exe") is None

    def test_minimal_pe_extracts_features(self, tmp_path):
        f = _write_minimal_pe(tmp_path)
        features = extract_pe_features(f)
        assert features is not None
        assert features.num_sections >= 1
        assert features.file_size > 0
        assert features.entry_point == 0x1000

    def test_feature_vector_length(self, tmp_path):
        f = _write_minimal_pe(tmp_path)
        features = extract_pe_features(f)
        assert features is not None
        vec = features.to_vector()
        assert len(vec) == 12  # 12 features in the model


# ---------------------------------------------------------------------------
# PE feature model (Isolation Forest)
# ---------------------------------------------------------------------------

class TestPEFeatureModel:
    def test_baseline_pe_is_inlier(self):
        """A PE with features matching the built-in baseline should be normal."""
        model = PEFeatureModel()
        normal_pe = PEFeatures(
            file_size=200000, num_sections=6, entry_point=0x1000,
            file_entropy=6.0, has_debug=True, has_signature=True,
            num_imports=80, num_exports=0, suspicious_section_count=0,
            avg_section_entropy=5.5, max_section_entropy=6.5,
            min_section_raw_size=512,
        )
        assert not model.is_suspicious(normal_pe)

    def test_anomalous_pe_is_outlier(self):
        """A PE with very abnormal features should be flagged as suspicious."""
        model = PEFeatureModel()
        weird_pe = PEFeatures(
            file_size=512,          # tiny
            num_sections=1,
            entry_point=0xFFFFF,    # unusually high
            file_entropy=7.99,      # near maximum (packed/encrypted)
            has_debug=False,
            has_signature=False,
            num_imports=0,          # no imports (abnormal for real exe)
            num_exports=0,
            suspicious_section_count=1,
            avg_section_entropy=7.9,
            max_section_entropy=7.99,
            min_section_raw_size=0, # zero raw size (suspicious)
        )
        assert model.is_suspicious(weird_pe)

    def test_anomaly_score_returns_float(self):
        model = PEFeatureModel()
        normal_pe = PEFeatures(
            file_size=200000, num_sections=6, entry_point=0x1000,
            file_entropy=6.0, has_debug=True, has_signature=True,
            num_imports=80, num_exports=0, suspicious_section_count=0,
            avg_section_entropy=5.5, max_section_entropy=6.5,
            min_section_raw_size=512,
        )
        score = model.anomaly_score(normal_pe)
        assert isinstance(score, float)


# ---------------------------------------------------------------------------
# Static classifier end-to-end
# ---------------------------------------------------------------------------

class TestStaticClassifierVTMalicious:
    def test_vt_malicious_emits_vt_positive(self, tmp_path):
        f = _write_text_file(tmp_path, "malware.exe")
        vt = _mock_vt_client("malicious", positives=25, total=70)
        cls = StaticClassifier(vt_client=vt)

        sigs = cls.classify_file_event(_file_write_event(str(f)))
        assert len(sigs) == 1
        assert sigs[0].kind == "vt_positive"
        assert sigs[0].engine == "static_classifier"
        assert "malware.exe" in sigs[0].reason


class TestStaticClassifierVTClean:
    def test_vt_clean_no_signal(self, tmp_path):
        f = _write_minimal_pe(tmp_path, "clean.exe")
        vt = _mock_vt_client("clean")
        cls = StaticClassifier(vt_client=vt)

        sigs = cls.classify_file_event(_file_write_event(str(f)))
        assert sigs == []


class TestStaticClassifierVTUnknown:
    def test_vt_unknown_suspicious_pe_emits_signal(self, tmp_path):
        f = _write_minimal_pe(tmp_path, "weird.exe")
        vt = _mock_vt_client("unknown")
        # Force the PE model to flag this file as suspicious.
        model = MagicMock(spec=PEFeatureModel)
        model.is_suspicious.return_value = True
        model.anomaly_score.return_value = -0.42
        cls = StaticClassifier(vt_client=vt, pe_model=model)

        sigs = cls.classify_file_event(_file_write_event(str(f)))
        assert len(sigs) == 1
        assert sigs[0].kind == "vt_unknown_suspicious_pe"
        assert sigs[0].engine == "static_classifier"

    def test_vt_unknown_normal_pe_no_signal(self, tmp_path):
        f = _write_minimal_pe(tmp_path, "normal.exe")
        vt = _mock_vt_client("unknown")
        model = MagicMock(spec=PEFeatureModel)
        model.is_suspicious.return_value = False
        cls = StaticClassifier(vt_client=vt, pe_model=model)

        sigs = cls.classify_file_event(_file_write_event(str(f)))
        assert sigs == []


class TestStaticClassifierOffline:
    def test_no_vt_client_suspicious_pe_still_fires(self, tmp_path):
        """Offline detection: VT disabled, PE model still works (NFR-7)."""
        f = _write_minimal_pe(tmp_path, "offline.exe")
        model = MagicMock(spec=PEFeatureModel)
        model.is_suspicious.return_value = True
        model.anomaly_score.return_value = -0.5
        cls = StaticClassifier(vt_client=None, pe_model=model)

        sigs = cls.classify_file_event(_file_write_event(str(f)))
        assert len(sigs) == 1
        assert sigs[0].kind == "vt_unknown_suspicious_pe"


class TestStaticClassifierDedup:
    def test_same_file_not_re_emitted(self, tmp_path):
        f = _write_text_file(tmp_path, "dup.exe", "payload")
        vt = _mock_vt_client("malicious", positives=10, total=60)
        cls = StaticClassifier(vt_client=vt)

        sigs1 = cls.classify_file_event(_file_write_event(str(f)))
        sigs2 = cls.classify_file_event(_file_write_event(str(f)))
        assert len(sigs1) == 1
        assert sigs2 == []

    def test_clear_hash_allows_re_check(self, tmp_path):
        f = _write_text_file(tmp_path, "recheck.exe", "data")
        vt = _mock_vt_client("malicious", positives=5, total=60)
        cls = StaticClassifier(vt_client=vt)
        sha = hashlib.sha256(b"data").hexdigest()

        cls.classify_file_event(_file_write_event(str(f)))
        cls.clear_hash(sha)
        sigs = cls.classify_file_event(_file_write_event(str(f)))
        assert len(sigs) == 1


class TestStaticClassifierEdgeCases:
    def test_non_file_write_event_ignored(self, tmp_path):
        ev = Event(
            timestamp=utc_timestamp(),
            source="network",
            event_type="connection",
        )
        cls = StaticClassifier()
        assert cls.classify_file_event(ev) == []

    def test_missing_path_no_crash(self):
        ev = Event(
            timestamp=utc_timestamp(),
            source="fs",
            event_type="file_write",
        )
        cls = StaticClassifier()
        assert cls.classify_file_event(ev) == []

    def test_nonexistent_file_no_crash(self, tmp_path):
        ev = _file_write_event(str(tmp_path / "does_not_exist.exe"))
        cls = StaticClassifier()
        assert cls.classify_file_event(ev) == []

    def test_non_pe_file_no_pe_signal(self, tmp_path):
        """Non-PE files should not trigger the PE model."""
        f = _write_text_file(tmp_path, "readme.txt", "just text")
        cls = StaticClassifier(vt_client=None)
        sigs = cls.classify_file_event(_file_write_event(str(f)))
        assert sigs == []

    def test_path_from_extra_field(self, tmp_path):
        """If image_path is None, fall back to extra['path']."""
        f = _write_text_file(tmp_path, "alt.txt", "content")
        vt = _mock_vt_client("malicious", positives=5, total=60)
        ev = Event(
            timestamp=utc_timestamp(),
            source="fs",
            event_type="file_write",
            extra={"path": str(f)},
        )
        cls = StaticClassifier(vt_client=vt)
        sigs = cls.classify_file_event(ev)
        assert len(sigs) == 1
        assert sigs[0].kind == "vt_positive"


class TestEICARHarness:
    """plan.md Section 7: the EICAR test file is the industry-standard
    harmless AV test string. It should be classified as malicious via VT
    (or at least processed without crashing). This test simulates a VT
    positive on the EICAR hash."""

    EICAR = (
        b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-"
        b"ANTIVIRUS-TEST-FILE!$H+H*"
    )

    def test_eicar_vt_positive(self, tmp_path):
        f = tmp_path / "eicar.com"
        f.write_bytes(self.EICAR)
        eicar_hash = hashlib.sha256(self.EICAR).hexdigest()
        vt = _mock_vt_client("malicious", positives=55, total=70)
        cls = StaticClassifier(vt_client=vt)

        sigs = cls.classify_file_event(_file_write_event(str(f)))
        assert len(sigs) == 1
        assert sigs[0].kind == "vt_positive"
        vt.lookup.assert_called_once_with(eicar_hash)

    def test_eicar_no_pe_signal_since_not_pe(self, tmp_path):
        """EICAR is not a PE — the PE model should not fire."""
        f = tmp_path / "eicar.com"
        f.write_bytes(self.EICAR)
        cls = StaticClassifier(vt_client=None)  # offline
        sigs = cls.classify_file_event(_file_write_event(str(f)))
        assert sigs == []  # not a PE, no VT → no signal
