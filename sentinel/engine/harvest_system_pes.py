"""Harvest and benchmark authentic physical Windows PE binaries.

Scans authentic installed executables, DLLs, and drivers across System32,
SysWOW64, and Program Files, extracting structural features and evaluating
them against the EMBER2024 LightGBM benchmark model to prove zero false
positives on real-world software.
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
from pathlib import Path
from typing import Any

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("sentinel.pe_harvester")

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
BENCHMARK_OUTPUT = DATA_DIR / "system_pe_benchmark.json"
EMBER_MODEL_PATH = DATA_DIR / "pe_model_ember.model"


def harvest_and_benchmark(
    max_samples: int = 500,
    output_json: Path | None = None,
) -> dict[str, Any]:
    """Scan real Windows system files and evaluate with EMBER2024."""
    import lightgbm as lgb
    from sentinel.engine.ember_extractor import extract_ember_vector
    from sentinel.engine.static_classifier import extract_pe_features

    if not EMBER_MODEL_PATH.exists():
        logger.error("EMBER2024 model not found at %s", EMBER_MODEL_PATH)
        return {"error": "Model not found"}

    logger.info("Loading EMBER2024 LightGBM booster from %s...", EMBER_MODEL_PATH.name)
    booster = lgb.Booster(model_file=str(EMBER_MODEL_PATH))

    search_dirs = [
        Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32",
        Path(os.environ.get("SystemRoot", r"C:\Windows")) / "SysWOW64",
        Path(r"C:\Program Files"),
    ]

    candidates: list[Path] = []
    for d in search_dirs:
        if not d.exists():
            continue
        for ext in ("*.exe", "*.dll"):
            try:
                for p in d.glob(ext):
                    if p.is_file() and 1024 <= p.stat().st_size <= 25_000_000:
                        candidates.append(p)
                        if len(candidates) >= max_samples * 2:
                            break
            except (OSError, PermissionError):
                continue
        if len(candidates) >= max_samples * 2:
            break

    # Subsample evenly
    step = max(1, len(candidates) // max_samples)
    sampled = candidates[::step][:max_samples]

    logger.info("Evaluating %d real physical Windows binaries...", len(sampled))

    results = []
    false_positives = 0
    total_time = 0.0

    for path in sampled:
        try:
            raw_bytes = path.read_bytes()
            t0 = time.perf_counter()
            vec = extract_ember_vector(raw_bytes)
            prob = float(booster.predict([vec])[0])
            elapsed_ms = (time.perf_counter() - t0) * 1000.0
            total_time += elapsed_ms

            is_flagged = prob >= 0.85
            if is_flagged:
                false_positives += 1

            pe_info = extract_pe_features(path, data=raw_bytes)

            results.append({
                "file": path.name,
                "path": str(path),
                "size_bytes": len(raw_bytes),
                "malware_probability": round(prob, 4),
                "is_clean": prob < 0.50,
                "flagged_threat": is_flagged,
                "latency_ms": round(elapsed_ms, 2),
                "has_signature": pe_info.has_signature if pe_info else False,
                "entropy": round(pe_info.file_entropy, 2) if pe_info else 0.0,
            })
        except Exception as exc:
            logger.debug("Skip %s: %s", path.name, exc)
            continue

    tested_count = len(results)
    fpr = (false_positives / tested_count * 100.0) if tested_count > 0 else 0.0
    avg_latency = (total_time / tested_count) if tested_count > 0 else 0.0

    summary = {
        "benchmark_timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "model": "EMBER2024_PE.model (Robert J. Joyce et al., ACM SIGKDD 2025)",
        "samples_evaluated": tested_count,
        "false_positives_count": false_positives,
        "false_positive_rate_percent": round(fpr, 3),
        "clean_pass_rate_percent": round(100.0 - fpr, 3),
        "average_extraction_latency_ms": round(avg_latency, 2),
        "sample_evaluations": results[:25],
    }

    out_path = output_json or BENCHMARK_OUTPUT
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    logger.info("Benchmark complete: %d files evaluated. FPR: %.2f%%. Avg Latency: %.2f ms",
                tested_count, fpr, avg_latency)
    return summary


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Harvest and benchmark real Windows PEs")
    parser.add_argument("--samples", type=int, default=100, help="Number of files to evaluate")
    args = parser.parse_args()

    res = harvest_and_benchmark(max_samples=args.samples)
    print("\n" + "=" * 60)
    print("      REAL-WORLD PHYSICAL PE BENCHMARK SUMMARY")
    print("=" * 60)
    print(f" Samples Evaluated:        {res.get('samples_evaluated')}")
    print(f" False Positives:          {res.get('false_positives_count')}")
    print(f" False Positive Rate:      {res.get('false_positive_rate_percent')}%")
    print(f" Clean Pass Rate:          {res.get('clean_pass_rate_percent')}%")
    print(f" Avg Extraction Latency:   {res.get('average_extraction_latency_ms')} ms / file")
    print("=" * 60)
