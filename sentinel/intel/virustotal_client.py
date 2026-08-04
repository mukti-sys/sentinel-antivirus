"""VirusTotal hash lookup client — rate-limit aware, cached in SQLite.

Implements architecture.md Section 5.7 (`intel/virustotal_client.py`) and
plan.md FAQ (free tier 4 requests/min; cache in events.db so the same hash
is never looked up twice). Only SHA-256 hashes are sent (NFR-7); file
content never leaves the machine.

When the API key is empty the client is disabled and returns None — core
behavioral detection still works fully offline (prd.md).
"""
from __future__ import annotations

import logging
import sqlite3
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import requests

logger = logging.getLogger(__name__)

_DEFAULT_DB_PATH = (
    Path(__file__).resolve().parent.parent / "data" / "events.db"
)
_VT_API = "https://www.virustotal.com/api/v3/files/{hash}"

# Free tier: 4 lookups/min (plan.md FAQ).
_DEFAULT_MIN_INTERVAL = 15.0  # seconds between requests

_CACHE_SCHEMA = """
CREATE TABLE IF NOT EXISTS hash_intel_cache (
    sha256      TEXT PRIMARY KEY,
    verdict     TEXT NOT NULL,
    positives   INTEGER,
    total       INTEGER,
    cached_at   REAL NOT NULL
);
"""


@dataclass(frozen=True)
class HashVerdict:
    """Result of a hash lookup (cache or live API)."""

    sha256: str
    verdict: str  # "clean" | "malicious" | "unknown"
    positives: int | None = None
    total: int | None = None
    from_cache: bool = False


class VirusTotalClient:
    """Rate-limited VirusTotal file-hash lookups with SQLite caching."""

    def __init__(
        self,
        api_key: str = "",
        db_path: str | Path = _DEFAULT_DB_PATH,
        min_interval: float = _DEFAULT_MIN_INTERVAL,
        session: requests.Session | None = None,
    ) -> None:
        self.api_key = (api_key or "").strip()
        self._db_path = Path(db_path)
        self._min_interval = min_interval
        self._session = session or requests.Session()
        self._lock = threading.Lock()
        self._last_request: float = 0.0
        self._conn: sqlite3.Connection | None = None

    @property
    def enabled(self) -> bool:
        return bool(self.api_key)

    def _connect(self) -> sqlite3.Connection:
        if self._conn is None:
            self._db_path.parent.mkdir(parents=True, exist_ok=True)
            self._conn = sqlite3.connect(str(self._db_path), check_same_thread=False)
            self._conn.row_factory = sqlite3.Row
            self._conn.execute(_CACHE_SCHEMA)
            self._conn.commit()
        return self._conn

    def close(self) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    def _normalize_hash(self, sha256: str) -> str:
        h = sha256.strip().lower()
        if h.endswith(" (sample)"):
            h = h.replace(" (sample)", "")
        return h

    def get_cached(self, sha256: str) -> HashVerdict | None:
        """Return a cached verdict if present."""
        h = self._normalize_hash(sha256)
        row = self._connect().execute(
            "SELECT sha256, verdict, positives, total FROM hash_intel_cache WHERE sha256=?",
            (h,),
        ).fetchone()
        if row is None:
            return None
        return HashVerdict(
            sha256=row["sha256"],
            verdict=row["verdict"],
            positives=row["positives"],
            total=row["total"],
            from_cache=True,
        )

    def _store_cache(self, verdict: HashVerdict) -> None:
        conn = self._connect()
        conn.execute(
            """
            INSERT INTO hash_intel_cache (sha256, verdict, positives, total, cached_at)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(sha256) DO UPDATE SET
                verdict=excluded.verdict,
                positives=excluded.positives,
                total=excluded.total,
                cached_at=excluded.cached_at
            """,
            (
                verdict.sha256,
                verdict.verdict,
                verdict.positives,
                verdict.total,
                time.time(),
            ),
        )
        conn.commit()

    def _wait_for_rate_limit(self) -> None:
        with self._lock:
            elapsed = time.time() - self._last_request
            if elapsed < self._min_interval:
                time.sleep(self._min_interval - elapsed)
            self._last_request = time.time()

    def _parse_response(self, sha256: str, data: dict[str, Any]) -> HashVerdict:
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats") or {}
        malicious = int(stats.get("malicious", 0))
        suspicious = int(stats.get("suspicious", 0))
        positives = malicious + suspicious
        total = sum(int(v) for v in stats.values()) if stats else None
        if positives > 0:
            verdict = "malicious"
        elif stats:
            verdict = "clean"
        else:
            verdict = "unknown"
        return HashVerdict(
            sha256=sha256,
            verdict=verdict,
            positives=positives,
            total=total,
            from_cache=False,
        )

    def lookup(self, sha256: str) -> HashVerdict | None:
        """Return verdict for `sha256`, using cache then live API.

        Returns None when disabled (no API key) or on HTTP 404 (hash unknown
        to VT — not yet seen). Caches all successful lookups.
        """
        h = self._normalize_hash(sha256)
        if len(h) != 64:
            return None

        cached = self.get_cached(h)
        if cached is not None:
            return cached

        if not self.enabled:
            return None

        self._wait_for_rate_limit()
        url = _VT_API.format(hash=h)
        headers = {"x-apikey": self.api_key, "Accept": "application/json"}
        try:
            resp = self._session.get(url, headers=headers, timeout=30)
        except requests.RequestException as exc:
            logger.warning("VirusTotal lookup failed for %s: %s", h[:12], exc)
            return None

        if resp.status_code == 404:
            verdict = HashVerdict(sha256=h, verdict="unknown", from_cache=False)
            self._store_cache(verdict)
            return verdict
        if resp.status_code == 429:
            logger.warning("VirusTotal rate limit hit for %s", h[:12])
            return None
        if not resp.ok:
            logger.warning(
                "VirusTotal HTTP %s for %s: %s",
                resp.status_code,
                h[:12],
                resp.text[:200],
            )
            return None

        verdict = self._parse_response(h, resp.json())
        self._store_cache(verdict)
        return verdict
