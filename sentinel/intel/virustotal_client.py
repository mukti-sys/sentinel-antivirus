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

import random
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


class TokenBucket:
    """Thread-safe Token Bucket rate limiter.

    Maintains capacity for bursts up to `capacity` tokens while replenishing
    at a steady rate of `refill_rate` tokens per second.
    """

    def __init__(self, capacity: float = 4.0, refill_rate: float = 4.0 / 60.0) -> None:
        self.capacity = float(capacity)
        self.refill_rate = float(refill_rate)
        self.tokens = float(capacity)
        self.last_update = time.time()
        self._lock = threading.Lock()

    def acquire(self, tokens: float = 1.0, timeout: float = 60.0) -> bool:
        """Attempt to acquire tokens, sleeping up to timeout. Returns True if acquired."""
        if self.refill_rate >= 1000.0:
            # Immediate/infinite mode for fast unit testing
            return True

        deadline = time.time() + timeout
        while True:
            with self._lock:
                now = time.time()
                elapsed = now - self.last_update
                self.last_update = now
                self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_rate)

                if self.tokens >= tokens:
                    self.tokens -= tokens
                    return True

                needed = tokens - self.tokens
                wait_time = needed / self.refill_rate

            if time.time() + wait_time > deadline:
                return False
            time.sleep(min(wait_time, 0.25))

    @property
    def available_tokens(self) -> float:
        with self._lock:
            now = time.time()
            elapsed = now - self.last_update
            return min(self.capacity, self.tokens + elapsed * self.refill_rate)


def is_eligible_for_vt_lookup(
    score_or_path: float | str | Path | None = None,
    is_signed: bool = False,
    *,
    score: float | None = None,
) -> bool:
    """Smart triage policy: only query VirusTotal for ambiguous or unverified files.

    Can be called with:
    1. A numeric score (float) via positional arg or score= kwarg:
       - Trusted signed binaries with score < 25.0 bypass VT entirely (preserves quota).
       - Obvious low-risk clean files with score <= 0 bypass VT.
       - Files with moderate suspicion (30.0 - 75.0) or unsigned suspicious PEs are queried.
    2. A file path (str or Path):
       - If the file has a valid Authenticode signature from Microsoft, bypass VT.
       - If unsigned or non-existent/suspicious, eligible for VT lookup.
    """
    if score is not None:
        score_val = float(score)
        if is_signed and score_val < 25.0:
            return False
        if score_val <= 0.0:
            return False
        return True

    if isinstance(score_or_path, (int, float)):
        score_val = float(score_or_path)
        if is_signed and score_val < 25.0:
            return False
        if score_val <= 0.0:
            return False
        return True

    # Path triage: check file signature and path
    try:
        p = Path(score_or_path)
        if not p.is_file():
            return True  # If not a physical file on disk (e.g. simulated or in-memory), allow lookup

        from sentinel.engine.authenticode import verify_pe_signature
        sig = verify_pe_signature(p)
        if sig.is_signed and sig.is_valid and sig.is_microsoft:
            return False  # Bypass VT for authentic Microsoft system files
    except Exception:
        pass

    return True


@dataclass(frozen=True)
class HashVerdict:
    """Result of a hash lookup (cache or live API)."""

    sha256: str
    verdict: str  # "clean" | "malicious" | "unknown"
    positives: int | None = None
    total: int | None = None
    from_cache: bool = False


class VirusTotalClient:
    """Rate-limited VirusTotal file-hash lookups with Token Bucket & SQLite caching."""

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

        # Token Bucket setup
        refill_rate = 10000.0 if min_interval <= 0.0 else (1.0 / min_interval)
        self.token_bucket = TokenBucket(capacity=4.0, refill_rate=refill_rate)

        # Exponential backoff state
        self._backoff_seconds: float = 0.0
        self._backoff_until: float = 0.0

        # Telemetry metrics
        self.total_queries: int = 0
        self.cache_hits: int = 0
        self.rate_limit_hits: int = 0
        self.network_errors: int = 0

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
        self.cache_hits += 1
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

    def _wait_for_rate_limit(self, timeout: float = 60.0) -> bool:
        """Wait for backoff, enforce min_interval, and acquire a token from the bucket."""
        now = time.time()
        if now < self._backoff_until:
            wait_rem = self._backoff_until - now
            if wait_rem > timeout:
                return False
            time.sleep(wait_rem)

        # Enforce minimum interval spacing between consecutive requests
        with self._lock:
            elapsed = time.time() - self._last_request
            if self._min_interval > 0.0 and elapsed < self._min_interval:
                time.sleep(self._min_interval - elapsed)
            self._last_request = time.time()

        return self.token_bucket.acquire(1.0, timeout=timeout)

    def get_telemetry(self) -> dict[str, Any]:
        """Return live telemetry metrics for GUI dashboard and audit logs."""
        now = time.time()
        return {
            "enabled": self.enabled,
            "total_queries": self.total_queries,
            "cache_hits": self.cache_hits,
            "rate_limit_hits": self.rate_limit_hits,
            "network_errors": self.network_errors,
            "tokens_available": round(self.token_bucket.available_tokens, 2),
            "backoff_active": now < self._backoff_until,
            "backoff_remaining_sec": max(0.0, round(self._backoff_until - now, 1)),
        }

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

        self.total_queries += 1
        acquired = self._wait_for_rate_limit(timeout=30.0)
        if not acquired:
            logger.warning("VirusTotal lookup aborted: Token Bucket rate limit timeout for %s", h[:12])
            return None

        url = _VT_API.format(hash=h)
        headers = {"x-apikey": self.api_key, "Accept": "application/json"}
        try:
            resp = self._session.get(url, headers=headers, timeout=30)
        except requests.RequestException as exc:
            self.network_errors += 1
            logger.warning("VirusTotal lookup failed for %s: %s", h[:12], exc)
            return None

        if resp.status_code == 404:
            verdict = HashVerdict(sha256=h, verdict="unknown", from_cache=False)
            self._store_cache(verdict)
            return verdict
        if resp.status_code == 429:
            self.rate_limit_hits += 1
            # Exponential backoff with jitter
            if self._backoff_seconds <= 0.0:
                self._backoff_seconds = 15.0
            else:
                self._backoff_seconds = min(120.0, self._backoff_seconds * 2.0)
            jitter = (random.random() * 4.0) - 2.0
            self._backoff_until = time.time() + max(5.0, self._backoff_seconds + jitter)
            logger.warning(
                "VirusTotal rate limit 429 hit for %s; backing off for %.1fs",
                h[:12],
                self._backoff_seconds + jitter,
            )
            return None
        if not resp.ok:
            logger.warning(
                "VirusTotal HTTP %s for %s: %s",
                resp.status_code,
                h[:12],
                resp.text[:200],
            )
            return None

        # Reset backoff on successful query
        self._backoff_seconds = 0.0
        self._backoff_until = 0.0

        verdict = self._parse_response(h, resp.json())
        self._store_cache(verdict)
        return verdict
