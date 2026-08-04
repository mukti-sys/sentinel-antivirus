"""Tests for intel/virustotal_client.py — the rate-limited, cached VT hash
lookup client (architecture.md Section 5.7, plan.md FAQ).

All HTTP calls are mocked — no real API requests. Tests cover:
- disabled client (empty API key) returns None
- cache hit bypasses HTTP
- live lookup parses response, caches result
- HTTP 404 → "unknown" verdict, cached
- HTTP 429 → rate limit, returns None
- rate limiting enforces minimum interval
- invalid hash (wrong length) → returns None
- malicious vs clean verdict parsing
"""
import sqlite3
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from sentinel.intel.virustotal_client import HashVerdict, VirusTotalClient

# A realistic SHA-256 hash (64 hex chars).
_HASH = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
_HASH2 = "a" * 64


def _make_client(tmp_path: Path, api_key: str = "test-key") -> VirusTotalClient:
    db = tmp_path / "test_cache.db"
    return VirusTotalClient(api_key=api_key, db_path=db, min_interval=0.0)


def _vt_response(malicious: int = 0, suspicious: int = 0, undetected: int = 60):
    """Build a minimal VT API v3 response body."""
    return {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": malicious,
                    "suspicious": suspicious,
                    "undetected": undetected,
                    "harmless": 0,
                }
            }
        }
    }


class TestDisabledClient:
    def test_empty_key_is_disabled(self, tmp_path):
        c = _make_client(tmp_path, api_key="")
        assert c.enabled is False

    def test_disabled_returns_none(self, tmp_path):
        c = _make_client(tmp_path, api_key="")
        assert c.lookup(_HASH) is None


class TestInvalidHash:
    def test_short_hash_returns_none(self, tmp_path):
        c = _make_client(tmp_path)
        assert c.lookup("abc123") is None

    def test_empty_hash_returns_none(self, tmp_path):
        c = _make_client(tmp_path)
        assert c.lookup("") is None


class TestCacheHit:
    def test_cached_verdict_bypasses_http(self, tmp_path):
        c = _make_client(tmp_path)
        # Seed the cache directly.
        conn = sqlite3.connect(str(tmp_path / "test_cache.db"))
        conn.execute(
            """CREATE TABLE IF NOT EXISTS hash_intel_cache (
                sha256 TEXT PRIMARY KEY, verdict TEXT NOT NULL,
                positives INTEGER, total INTEGER, cached_at REAL NOT NULL)"""
        )
        conn.execute(
            "INSERT INTO hash_intel_cache VALUES (?, 'clean', 0, 60, ?)",
            (_HASH, time.time()),
        )
        conn.commit()
        conn.close()

        result = c.lookup(_HASH)
        assert result is not None
        assert result.verdict == "clean"
        assert result.from_cache is True


class TestLiveLookup:
    def test_malicious_verdict(self, tmp_path):
        c = _make_client(tmp_path)
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.ok = True
        mock_resp.json.return_value = _vt_response(malicious=15, suspicious=2)
        c._session = MagicMock()
        c._session.get.return_value = mock_resp

        result = c.lookup(_HASH)
        assert result is not None
        assert result.verdict == "malicious"
        assert result.positives == 17
        assert result.from_cache is False
        # Verify it was cached.
        cached = c.get_cached(_HASH)
        assert cached is not None
        assert cached.verdict == "malicious"

    def test_clean_verdict(self, tmp_path):
        c = _make_client(tmp_path)
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.ok = True
        mock_resp.json.return_value = _vt_response(malicious=0, undetected=70)
        c._session = MagicMock()
        c._session.get.return_value = mock_resp

        result = c.lookup(_HASH2)
        assert result is not None
        assert result.verdict == "clean"
        assert result.positives == 0

    def test_http_404_returns_unknown_and_caches(self, tmp_path):
        c = _make_client(tmp_path)
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        c._session = MagicMock()
        c._session.get.return_value = mock_resp

        result = c.lookup(_HASH)
        assert result is not None
        assert result.verdict == "unknown"
        # Should be cached so a second lookup doesn't hit HTTP again.
        c._session.get.reset_mock()
        result2 = c.lookup(_HASH)
        assert result2 is not None
        assert result2.from_cache is True
        c._session.get.assert_not_called()

    def test_http_429_returns_none(self, tmp_path):
        c = _make_client(tmp_path)
        mock_resp = MagicMock()
        mock_resp.status_code = 429
        mock_resp.ok = False
        c._session = MagicMock()
        c._session.get.return_value = mock_resp

        result = c.lookup(_HASH)
        assert result is None

    def test_http_500_returns_none(self, tmp_path):
        c = _make_client(tmp_path)
        mock_resp = MagicMock()
        mock_resp.status_code = 500
        mock_resp.ok = False
        mock_resp.text = "Internal Server Error"
        c._session = MagicMock()
        c._session.get.return_value = mock_resp

        result = c.lookup(_HASH)
        assert result is None

    def test_request_exception_returns_none(self, tmp_path):
        import requests

        c = _make_client(tmp_path)
        c._session = MagicMock()
        c._session.get.side_effect = requests.ConnectionError("network down")

        result = c.lookup(_HASH)
        assert result is None


class TestRateLimiting:
    def test_enforces_minimum_interval(self, tmp_path):
        c = _make_client(tmp_path)
        c._min_interval = 0.5  # 500ms between requests
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.ok = True
        mock_resp.json.return_value = _vt_response()
        c._session = MagicMock()
        c._session.get.return_value = mock_resp

        start = time.time()
        c.lookup(_HASH)
        c.lookup(_HASH2)  # second lookup on a different hash
        elapsed = time.time() - start
        # The second call should have waited ~0.5s.
        assert elapsed >= 0.4, f"rate limit not enforced: {elapsed:.2f}s"


class TestHashNormalization:
    def test_uppercase_hash_normalized(self, tmp_path):
        c = _make_client(tmp_path, api_key="")
        # Seed cache with lowercase.
        conn = sqlite3.connect(str(tmp_path / "test_cache.db"))
        conn.execute(
            """CREATE TABLE IF NOT EXISTS hash_intel_cache (
                sha256 TEXT PRIMARY KEY, verdict TEXT NOT NULL,
                positives INTEGER, total INTEGER, cached_at REAL NOT NULL)"""
        )
        conn.execute(
            "INSERT INTO hash_intel_cache VALUES (?, 'clean', 0, 60, ?)",
            (_HASH, time.time()),
        )
        conn.commit()
        conn.close()

        # Lookup with uppercase should still hit the cache.
        result = c.get_cached(_HASH.upper())
        assert result is not None
        assert result.verdict == "clean"
