"""Benchmark comparing Sentinel Native Rust Core vs Pure-Python Execution."""

import hashlib
import os
import tempfile
import time
from pathlib import Path

from sentinel.engine import native_core
from sentinel.sensors.fs_sensor import shannon_entropy as py_shannon_entropy


def benchmark_hashing():
    print("=" * 70)
    print(" BENCHMARK 1: STREAMING SHA-256 HASHING")
    print("=" * 70)

    sizes_mb = [10, 50]
    with tempfile.TemporaryDirectory() as tmpdir:
        for size_mb in sizes_mb:
            fpath = Path(tmpdir) / f"test_{size_mb}mb.bin"
            # Generate deterministic dummy data
            chunk = os.urandom(1024 * 1024)
            with open(fpath, "wb") as f:
                for _ in range(size_mb):
                    f.write(chunk)

            # 1. Pure Python read + hashlib
            t0 = time.perf_counter()
            h = hashlib.sha256()
            with open(fpath, "rb") as f:
                while c := f.read(65536):
                    h.update(c)
            py_hash = h.hexdigest()
            t_py = time.perf_counter() - t0

            # 2. Native Rust streaming hash
            t0 = time.perf_counter()
            nat_hash = native_core.fast_sha256(fpath)
            t_nat = time.perf_counter() - t0

            assert py_hash == nat_hash, "Hash mismatch!"

            speedup = (t_py / t_nat) if t_nat > 0 else 1.0
            print(f"File Size: {size_mb:>3} MB")
            print(f"  Python hashlib : {t_py*1000:>7.2f} ms ({size_mb/t_py:>7.1f} MB/s)")
            print(f"  Native Rust    : {t_nat*1000:>7.2f} ms ({size_mb/t_nat:>7.1f} MB/s)")
            print(f"  Speedup Factor : {speedup:.2f}x faster")
            print("-" * 70)


def benchmark_entropy():
    print("\n" + "=" * 70)
    print(" BENCHMARK 2: SHANNON ENTROPY COMPUTATION (10,000 BLOCKS)")
    print("=" * 70)

    # 10,000 blocks of 4KB each (typical section/packet size)
    blocks = [os.urandom(4096) for _ in range(1000)]

    # 1. Pure Python entropy
    t0 = time.perf_counter()
    for b in blocks:
        py_shannon_entropy(b)
    t_py = time.perf_counter() - t0

    # 2. Native Rust entropy
    t0 = time.perf_counter()
    for b in blocks:
        native_core.fast_entropy(b)
    t_nat = time.perf_counter() - t0

    speedup = (t_py / t_nat) if t_nat > 0 else 1.0
    print(f"Processed 1,000 x 4KB blocks (4 MB total):")
    print(f"  Python loop    : {t_py*1000:>7.2f} ms")
    print(f"  Native Rust    : {t_nat*1000:>7.2f} ms")
    print(f"  Speedup Factor : {speedup:.2f}x faster")
    print("=" * 70)


if __name__ == "__main__":
    print(f"Sentinel Native Core: {native_core.get_native_version()} (Available: {native_core.is_native_available()})\n")
    benchmark_hashing()
    benchmark_entropy()
