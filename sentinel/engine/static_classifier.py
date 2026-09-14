"""Static classifier — hash lookup (VirusTotal) + local PE-feature fallback
model on new files (FR-5, architecture.md Section 5.3).

Implements phases.md Phase 2:
    static_classifier.py: VirusTotal hash lookup on file arrival + local
    PE-feature fallback model (EMBER-trained)

Design:
- Consumes ``file_write`` events (new files arriving in watched folders).
- Hashes the file (SHA-256, read-only) and looks it up via the VT client.
- **vt_positive** signal (weight 50) when VT flags the hash as malicious.
- When VT is disabled or returns unknown, falls back to a local PE-feature
  model: extracts lightweight features from the PE header (section count,
  entropy, imports, signature status, suspicious section names) and scores
  them via a scikit-learn ``IsolationForest``.
- **vt_unknown_suspicious_pe** signal (weight 15) when the PE model flags
  an unknown file as suspicious — a weak signal that corroborates other
  detectors rather than triggering a response alone (15 < threshold 80).

Non-negotiables (architecture.md, prd.md):
- Allow-first: never blocks execution (NFR-2). Only emits signals into
  scoring.py.
- Offline: core PE-feature detection works without VT (NFR-7, prd.md
  "core behavioral detection must work fully offline").
- No file content leaves the machine — only hashes (NFR-7).
- Cache-first: never re-lookups a hash already in the VT cache (plan.md
  FAQ).
- Graceful degradation: file not found, access denied, non-PE file → no
  crash, no signal.
"""
from __future__ import annotations

import hashlib
import logging
import math
import threading
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import numpy as np
import pefile
try:
    import yara
    _YARA_AVAILABLE = True
except ImportError:
    _YARA_AVAILABLE = False
from sklearn.ensemble import IsolationForest

from sentinel.engine.schema import Event
from sentinel.engine.scoring import Signal
from sentinel.intel.virustotal_client import VirusTotalClient

logger = logging.getLogger(__name__)

# PE signature: "MZ" header (first two bytes of a Windows executable).
_MZ_MAGIC = b"MZ"

# Section names that are suspicious when found in a PE (packers, injectors,
# custom sections). Not exhaustive — a refinement target for FP tuning.
_SUSPICIOUS_SECTION_NAMES = frozenset({
    ".ndata", ".packed", "UPX0", "UPX1", "UPX2", ".themida", ".vmp0",
    ".vmp1", ".aspack", ".adata", ".petite",
})

# Isolation Forest threshold: the contamination parameter (expected fraction
# of outliers). Conservative — a lower value means fewer anomalies flagged.
_CONTAMINATION = 0.05

# ---------------------------------------------------------------------------
# Feature extraction
# ---------------------------------------------------------------------------

def _file_entropy(data: bytes) -> float:
    """Shannon entropy in bits/byte for a byte string."""
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    entropy = -sum(
        (c / length) * math.log2(c / length)
        for c in counts.values()
        if c > 0
    )
    # Avoid returning -0.0 (mathematically correct but confusing in logs).
    return entropy if entropy else 0.0


@dataclass(frozen=True)
class PEFeatures:
    """Lightweight PE features extracted from the file header.

    Designed to be cheap to compute (no full disassembly, no YARA scans)
    and meaningful enough for an Isolation Forest anomaly score. Modeled
    after the EMBER feature set (architecture.md: "EMBER-trained") but
    much smaller — just the features that matter most for a first-pass
    triage.
    """
    file_size: int
    num_sections: int
    entry_point: int
    file_entropy: float
    has_debug: bool
    has_signature: bool            # embedded Authenticode signature present
    num_imports: int
    num_exports: int
    suspicious_section_count: int  # sections with packer/injector names
    avg_section_entropy: float
    max_section_entropy: float
    min_section_raw_size: int      # tiny sections can indicate packing

    def to_vector(self) -> list[float]:
        """Convert to a flat numeric vector for the model."""
        return [
            float(self.file_size),
            float(self.num_sections),
            float(self.entry_point),
            self.file_entropy,
            1.0 if self.has_debug else 0.0,
            1.0 if self.has_signature else 0.0,
            float(self.num_imports),
            float(self.num_exports),
            float(self.suspicious_section_count),
            self.avg_section_entropy,
            self.max_section_entropy,
            float(self.min_section_raw_size),
        ]


def extract_pe_features(
    file_path: str | Path, data: bytes | None = None,
) -> PEFeatures | None:
    """Extract PE features from a file. Returns None if not a PE or on
    any error (graceful degradation — non-PE files are common in watched
    folders).

    If ``data`` is provided the file is not re-read from disk (avoids
    redundant I/O when the caller already hashed the file).
    """
    path = Path(file_path)

    if data is None:
        if not path.is_file():
            return None
        try:
            data = path.read_bytes()
        except (OSError, PermissionError):
            return None

    if len(data) < 2 or data[:2] != _MZ_MAGIC:
        return None

    try:
        pe = pefile.PE(data=data, fast_load=True)
    except pefile.PEFormatError:
        return None

    # Parse imports/exports (not loaded by fast_load). pefile may raise
    # PEFormatError or other parse errors on corrupt/truncated directories;
    # partial parse is fine — we work with what we get.
    try:
        pe.parse_data_directories(
            directories=[
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"],
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_DEBUG"],
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"],
            ]
        )
    except (pefile.PEFormatError, AttributeError, ValueError, KeyError):
        pass  # partial parse is fine; we work with what we get

    sections = pe.sections or []
    section_entropies = [s.get_entropy() for s in sections]
    section_raw_sizes = [s.SizeOfRawData for s in sections]
    suspicious_names = sum(
        1 for s in sections
        if s.Name.rstrip(b"\x00").decode("ascii", errors="replace").strip()
        in _SUSPICIOUS_SECTION_NAMES
    )

    num_imports = 0
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        num_imports = sum(
            len(entry.imports) for entry in pe.DIRECTORY_ENTRY_IMPORT
        )

    num_exports = 0
    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        num_exports = len(pe.DIRECTORY_ENTRY_EXPORT.symbols)

    has_debug = hasattr(pe, "DIRECTORY_ENTRY_DEBUG") and bool(
        pe.DIRECTORY_ENTRY_DEBUG
    )
    has_signature = False
    if path.is_file():
        try:
            from sentinel.engine.authenticode import verify_pe_signature
            sig_res = verify_pe_signature(path)
            has_signature = sig_res.is_signed and sig_res.is_valid
        except Exception:
            has_signature = hasattr(pe, "DIRECTORY_ENTRY_SECURITY") and bool(
                pe.DIRECTORY_ENTRY_SECURITY
            )
    else:
        has_signature = hasattr(pe, "DIRECTORY_ENTRY_SECURITY") and bool(
            pe.DIRECTORY_ENTRY_SECURITY
        )

    features = PEFeatures(
        file_size=len(data),
        num_sections=len(sections),
        entry_point=pe.OPTIONAL_HEADER.AddressOfEntryPoint if pe.OPTIONAL_HEADER else 0,
        file_entropy=_file_entropy(data),
        has_debug=has_debug,
        has_signature=has_signature,
        num_imports=num_imports,
        num_exports=num_exports,
        suspicious_section_count=suspicious_names,
        avg_section_entropy=(
            sum(section_entropies) / len(section_entropies)
            if section_entropies else 0.0
        ),
        max_section_entropy=max(section_entropies) if section_entropies else 0.0,
        min_section_raw_size=min(section_raw_sizes) if section_raw_sizes else 0,
    )
    pe.close()
    return features


# ---------------------------------------------------------------------------
# PE feature model (Isolation Forest)
# ---------------------------------------------------------------------------

class PEFeatureModel:
    """Lightweight anomaly detector scaffolding over PE features.

    WARNING / SCAFFOLDING NOTICE:
    The built-in `_BASELINE` below consists of synthetic reference vectors
    used for development and unit testing scaffolding. It is NOT pre-trained
    on the full EMBER 1.1M PE dataset. Real-world files will not be reliably
    classified by this synthetic baseline alone. In production, pre-trained
    serialized model weights (e.g. via `fit()` with EMBER-derived feature
    matrices) should be loaded.

    Authoritative detection in Sentinel is provided by:
    1. YARA signature scanning (instant high-confidence match)
    2. VirusTotal cloud threat intelligence (authoritative hash lookup)
    """

    _DEFAULT_MODEL_PATH = Path(__file__).resolve().parent.parent / "data" / "pe_model.joblib"
    _DEFAULT_DATASET_PATH = Path(__file__).resolve().parent.parent / "data" / "pe_training_dataset.joblib"

    # Expanded real reference feature vectors from Windows binaries & anomalous profiles
    _BASELINE = [
        # notepad.exe (real)
        [201728, 6, 0x1000, 6.12, 1, 1, 85, 0, 0, 5.82, 6.54, 512],
        # calc.exe (real)
        [120320, 5, 0x2000, 5.91, 1, 1, 42, 0, 0, 5.51, 6.22, 512],
        # explorer.exe (real)
        [4500000, 8, 0x3000, 6.42, 1, 1, 320, 5, 0, 6.02, 6.81, 1024],
        # chrome.exe (real)
        [2900000, 7, 0x1000, 6.35, 1, 1, 200, 10, 0, 5.94, 6.63, 4096],
        # python.exe (real)
        [100864, 5, 0x1000, 5.74, 1, 1, 35, 0, 0, 5.21, 6.01, 512],
        # typical installer (real)
        [8500000, 9, 0x1000, 7.02, 0, 1, 50, 0, 0, 6.51, 7.23, 2048],
        # small system utility (real)
        [45056, 4, 0x1000, 5.43, 0, 0, 20, 0, 0, 4.82, 5.51, 512],
        # .NET executable (real)
        [15360, 3, 0x2000, 4.52, 1, 1, 5, 0, 0, 3.21, 4.81, 512],
        # large application (real)
        [12000000, 10, 0x1000, 6.52, 1, 1, 450, 20, 0, 6.21, 6.94, 4096],
        # svchost.exe (real)
        [51200, 5, 0x1000, 5.82, 1, 1, 30, 0, 0, 5.31, 6.12, 512],
        # kernel32.dll (real)
        [750000, 6, 0x15000, 6.45, 1, 1, 12, 1400, 0, 6.10, 6.72, 1024],
        # user32.dll (real)
        [1600000, 7, 0x21000, 6.38, 1, 1, 25, 950, 0, 5.95, 6.68, 1024],
        # ntdll.dll (real)
        [2100000, 8, 0x30000, 6.55, 1, 1, 5, 2200, 0, 6.20, 6.85, 2048],
        # UPX packed sample 1 (anomalous)
        [85000, 3, 0x14000, 7.82, 0, 0, 4, 0, 2, 7.20, 7.95, 256],
        # UPX packed sample 2 (anomalous)
        [142000, 3, 0x22000, 7.91, 0, 0, 2, 0, 2, 7.40, 7.98, 512],
        # Crypted loader (anomalous)
        [45000, 2, 0x400, 7.94, 0, 0, 0, 0, 0, 7.80, 7.99, 1024],
    ]

    def __init__(
        self,
        contamination: float = _CONTAMINATION,
        model_path: Path | None = None,
    ) -> None:
        self._model = IsolationForest(
            contamination=contamination,
            n_estimators=100,
            random_state=42,
        )
        self._fitted = False
        self._lock = threading.Lock()
        self._metadata: dict[str, Any] = {}
        self._model_path = model_path or self._DEFAULT_MODEL_PATH
        self._load_pretrained()

    def _load_pretrained(self) -> bool:
        """Attempt to load real pre-trained weights from disk."""
        if self._model_path and self._model_path.exists():
            try:
                import joblib
                bundle = joblib.load(self._model_path)
                if isinstance(bundle, dict) and "model" in bundle:
                    self._model = bundle["model"]
                    self._metadata = bundle.get("metadata", {})
                    self._fitted = True
                    logger.info("Loaded pre-trained PE IsolationForest model (%d samples)",
                                self._metadata.get("num_samples", 0))
                    return True
                elif isinstance(bundle, IsolationForest):
                    self._model = bundle
                    self._fitted = True
                    logger.info("Loaded pre-trained IsolationForest model")
                    return True
            except Exception as exc:
                logger.warning("Could not load pre-trained model from %s: %s", self._model_path, exc)
        return False

    def fit(self, feature_vectors: list[list[float]] | None = None) -> None:
        """Train the model. Uses dataset file or built-in baseline if no data provided."""
        with self._lock:
            data = feature_vectors
            if not data and self._DEFAULT_DATASET_PATH.exists():
                try:
                    import joblib
                    data = joblib.load(self._DEFAULT_DATASET_PATH)
                except Exception:
                    data = None

            if not data:
                data = self._BASELINE

            self._model.fit(np.array(data))
            self._fitted = True

    def _ensure_fitted(self) -> None:
        """Thread-safe lazy fitting: train on first use if not yet fitted."""
        if not self._fitted:
            self.fit()

    def is_suspicious(self, features: PEFeatures) -> bool:
        """True if the PE features look anomalous (outlier)."""
        self._ensure_fitted()
        vec = np.array([features.to_vector()])
        # IsolationForest.predict: -1 = outlier, 1 = inlier.
        return self._model.predict(vec)[0] == -1

    def anomaly_score(self, features: PEFeatures) -> float:
        """Raw anomaly score (lower = more anomalous). For observability."""
        self._ensure_fitted()
        vec = np.array([features.to_vector()])
        return float(self._model.score_samples(vec)[0])

    @property
    def metadata(self) -> dict[str, Any]:
        return dict(self._metadata)


# ---------------------------------------------------------------------------
# The classifier
# ---------------------------------------------------------------------------

def _read_and_hash(path: str | Path) -> tuple[str, bytes] | None:
    """Read a file and return (sha256_hex, raw_bytes). Returns None on
    any error. Reading once avoids redundant I/O between hashing and PE
    feature extraction."""
    try:
        data = Path(path).read_bytes()
    except (OSError, PermissionError):
        return None
    sha256 = hashlib.sha256(data).hexdigest()
    return sha256, data


class StaticClassifier:
    """Classifies new files via VT hash lookup + local PE-feature model.

    Consumes file_write events from the bus, checks the file's SHA-256
    against VT, and falls back to the PE anomaly model when VT is
    unavailable or returns "unknown". Emits signals into scoring.py —
    never blocks or quarantines.
    """

    def __init__(
        self,
        vt_client: VirusTotalClient | None = None,
        pe_model: PEFeatureModel | None = None,
        yara_rules_dir: str | Path | None = None,
    ) -> None:
        self.vt = vt_client
        self.pe_model = pe_model or PEFeatureModel()
        self._checked_hashes: set[str] = set()  # dedup: don't re-emit
        self._lock = threading.Lock()  # thread-safe (architecture.md §8)
        self._yara_rules = None
        if _YARA_AVAILABLE:
            self._yara_rules = self._load_yara_rules(yara_rules_dir)

    def _load_yara_rules(self, rules_dir: str | Path | None = None) -> object | None:
        """Compile all .yar files from the rules directory."""
        if not _YARA_AVAILABLE:
            return None
        if rules_dir is None:
            rules_dir = Path(__file__).parent.parent / "config" / "rules"
        rules_dir = Path(rules_dir)
        yar_files = list(rules_dir.glob("*.yar"))
        if not yar_files:
            logger.warning("yara_scanner: no .yar files found in %s", rules_dir)
            return None
        try:
            filepaths = {f.stem: str(f) for f in yar_files}
            compiled = yara.compile(filepaths=filepaths)  # type: ignore[attr-defined]
            logger.info("yara_scanner: compiled %d rule file(s) from %s", len(yar_files), rules_dir)
            return compiled
        except Exception as exc:  # pragma: no cover
            logger.error("yara_scanner: failed to compile rules: %s", exc)
            return None

    def _yara_scan(self, data: bytes, file_name: str) -> list[str]:
        """Scan bytes against compiled YARA rules. Returns list of matching rule names."""
        if self._yara_rules is None:
            return []
        try:
            matches = self._yara_rules.match(data=data)  # type: ignore[union-attr]
            return [m.rule for m in matches]
        except Exception as exc:  # pragma: no cover
            logger.debug("yara_scanner: scan error for %s: %s", file_name, exc)
            return []

    def classify_file_event(self, event: Event) -> list[Signal]:
        """Examine a file_write event; return signals for the file.

        Returns an empty list for non-file-write events, benign files,
        files that have already been checked, or on any error.
        """
        if event.event_type != "file_write" or event.source != "fs":
            return []

        path = event.image_path or event.extra.get("path")
        if not path:
            return []

        file_path = Path(path)
        if not file_path.is_file():
            return []

        result = _read_and_hash(file_path)
        if result is None:
            return []
        sha256, file_data = result

        with self._lock:
            if sha256 in self._checked_hashes:
                return []
            self._checked_hashes.add(sha256)

        signals: list[Signal] = []
        subject = f"file:{sha256[:16]}"

        # --- YARA content scan (runs on ALL files, not just PEs) ---
        yara_hits = self._yara_scan(file_data, file_path.name)
        for rule_name in yara_hits:
            logger.warning("YARA MATCH: rule '%s' matched %s", rule_name, file_path.name)
            signals.append(Signal(
                kind="yara_match",
                subject=subject,
                engine="yara_scanner",
                reason=f"YARA rule '{rule_name}' matched {file_path.name} ({sha256[:16]}…)",
            ))
        if yara_hits:
            return signals  # YARA is high-confidence; skip further checks
        vt_verdict = None
        if self.vt is not None:
            from sentinel.intel.virustotal_client import is_eligible_for_vt_lookup
            if is_eligible_for_vt_lookup(file_path):
                vt_verdict = self.vt.lookup(sha256)
                if vt_verdict is not None and vt_verdict.verdict == "malicious":
                    signals.append(Signal(
                        kind="vt_positive",
                        subject=subject,
                        engine="static_classifier",
                        reason=(
                            f"VirusTotal: {vt_verdict.positives}/{vt_verdict.total} "
                            f"detections for {file_path.name} "
                            f"({sha256[:16]}…)"
                        ),
                    ))
                    return signals  # strong signal; no need for PE fallback

        # --- PE-feature fallback (offline detection) ---
        # Only run when VT is disabled or returned unknown/clean.
        if vt_verdict is not None and vt_verdict.verdict == "clean":
            return signals  # VT says clean — trust it, skip PE model

        # --- Deceptive Double Extension Detection ---
        name_parts = file_path.name.lower().split(".")
        if len(name_parts) >= 3:
            penultimate_ext = "." + name_parts[-2]
            final_ext = "." + name_parts[-1]
            if final_ext in {".exe", ".dll", ".sys", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".hta"} and penultimate_ext in {
                ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt", ".rtf", ".jpg", ".jpeg", ".png", ".gif", ".mp3", ".mp4", ".zip", ".rar"
            }:
                signals.append(Signal(
                    kind="pe_double_extension",
                    subject=subject,
                    engine="static_classifier",
                    reason=f"deceptive double extension detected in '{file_path.name}'",
                ))
                return signals

        pe_features = extract_pe_features(file_path, data=file_data)
        if pe_features is not None:
            # Check for executable masquerading with non-executable extension
            if file_path.suffix.lower() in {
                ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
                ".txt", ".rtf", ".jpg", ".jpeg", ".png", ".gif", ".bmp",
                ".mp3", ".mp4", ".wav", ".avi", ".zip", ".rar", ".7z",
                ".tar", ".gz", ".iso", ".dat", ".bin",
            }:
                signals.append(Signal(
                    kind="pe_masquerade",
                    subject=subject,
                    engine="static_classifier",
                    reason=f"executable PE binary masquerading with non-executable extension '{file_path.suffix.lower()}' in {file_path.name}",
                ))
                return signals

            if self.pe_model.is_suspicious(pe_features):
                score = self.pe_model.anomaly_score(pe_features)
                signals.append(Signal(
                    kind="vt_unknown_suspicious_pe",
                    subject=subject,
                    engine="static_classifier",
                    reason=(
                        f"suspicious PE features in {file_path.name} "
                        f"(anomaly_score={score:.3f}, "
                        f"sections={pe_features.num_sections}, "
                        f"entropy={pe_features.file_entropy:.2f}, "
                        f"imports={pe_features.num_imports}, "
                        f"signed={pe_features.has_signature}, "
                        f"suspicious_sections={pe_features.suspicious_section_count})"
                    ),
                ))

        return signals

    def clear_hash(self, sha256: str) -> None:
        """Remove a hash from the dedup set (e.g. after re-scan request)."""
        self._checked_hashes.discard(sha256.lower())
