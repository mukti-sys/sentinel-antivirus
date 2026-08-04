"""Tests for engine/scoring.py — the false-positive lever (NFR-1) and the
architecture.md Section 5.3 DLL / image-load layered handling.

The core guarantees under test:
- no single weak signal triggers a response alone
- self-loads are ignored; only cross-process injection counts
- reflective/manual mapping >> routine LoadLibrary
- unsigned ≠ guilty (needs corroboration)
- reputation cache stops reputable DLLs/publishers contributing
- publisher/hash allowlist is surgical (not folder-wide)
"""
import pytest

from sentinel.engine.scoring import (
    DllLoadContext,
    DllReputationCache,
    Scorer,
    Signal,
    WEIGHTS,
    score_dll_load,
)


# --------------------------------------------------------------------------- #
# Basic scoring / threshold
# --------------------------------------------------------------------------- #
def test_single_weak_signal_does_not_cross_threshold():
    s = Scorer(threshold=80.0)
    s.add_signal(Signal(kind="rule_match_medium", subject="pid:1", reason="r"))
    assert not s.crosses_threshold("pid:1")
    assert not s.should_respond("pid:1")


def test_combined_signals_cross_threshold_and_respond():
    s = Scorer(threshold=80.0)
    s.add_signal(Signal(kind="cpu_sustained", subject="pid:1", reason="90% cpu"))      # 30
    s.add_signal(Signal(kind="stratum_network", subject="pid:1", reason="pool"))        # 30
    s.add_signal(Signal(kind="rule_match_medium", subject="pid:1", reason="lolbin"))    # 20
    assert s.get("pid:1").total == 80.0
    assert s.crosses_threshold("pid:1")
    assert s.should_respond("pid:1")


def test_below_threshold_never_responds():
    s = Scorer(threshold=80.0)
    s.add_signal(Signal(kind="cpu_sustained", subject="pid:1", reason="x"))  # 30
    s.add_signal(Signal(kind="stratum_network", subject="pid:1", reason="y"))  # 30 -> 60
    assert s.get("pid:1").total == 60.0
    assert not s.should_respond("pid:1")


# --------------------------------------------------------------------------- #
# DLL layered handling
# --------------------------------------------------------------------------- #
def test_self_load_is_ignored():
    rep = DllReputationCache()
    ctx = DllLoadContext(
        dll_hash="abc", publisher="Acme",
        loader_pid=100, target_pid=100,  # same pid -> self-load
        signed=False,
    )
    sigs = score_dll_load(ctx, rep)
    assert sigs == []


def test_unsigned_dll_alone_never_responds():
    # architecture.md 5.3: unsigned DLL alone is not sufficient.
    rep = DllReputationCache()
    s = Scorer(threshold=80.0)
    ctx = DllLoadContext(
        dll_hash="abc", loader_pid=100, target_pid=200,  # cross-process
        signed=False, host_normally_injected=True,
        has_cpu_anomaly=False, has_network_anomaly=False,
    )
    for sig in score_dll_load(ctx, rep):
        s.add_signal(sig)
    # Only cross_process (25) should be present; unsigned not added (no corroboration)
    kinds = {sig.kind for sig in s.get("pid:200").signals}
    assert "dll_cross_process" in kinds
    assert "dll_unsigned" not in kinds
    assert not s.should_respond("pid:200")


def test_cross_process_injection_alone_below_threshold():
    rep = DllReputationCache()
    s = Scorer(threshold=80.0)
    ctx = DllLoadContext(loader_pid=100, target_pid=200, signed=True)
    for sig in score_dll_load(ctx, rep):
        s.add_signal(sig)
    assert s.get("pid:200").total == WEIGHTS["dll_cross_process"]  # 25
    assert not s.should_respond("pid:200")


def test_reflective_mapping_is_weighted_high():
    rep = DllReputationCache()
    s = Scorer(threshold=80.0)
    ctx = DllLoadContext(
        loader_pid=100, target_pid=200, signed=True, reflective=True
    )
    for sig in score_dll_load(ctx, rep):
        s.add_signal(sig)
    kinds = {sig.kind for sig in s.get("pid:200").signals}
    assert "dll_reflective" in kinds  # 45
    # reflective (45) + cross_process (25) = 70, below 80 alone -> no respond
    assert s.get("pid:200").total == 70.0
    assert not s.should_respond("pid:200")


def test_reflective_plus_one_corroboration_responds():
    rep = DllReputationCache()
    s = Scorer(threshold=80.0)
    ctx = DllLoadContext(
        loader_pid=100, target_pid=200, signed=True, reflective=True,
        host_normally_injected=False,  # abnormal host adds 15
    )
    for sig in score_dll_load(ctx, rep):
        s.add_signal(sig)
    # reflective 45 + cross_process 25 + abnormal_host 15 = 85 >= 80 -> respond
    assert s.get("pid:200").total == 85.0
    assert s.should_respond("pid:200")


def test_unsigned_contributes_when_paired_with_anomaly():
    rep = DllReputationCache()
    ctx = DllLoadContext(
        dll_hash="abc", loader_pid=100, target_pid=200,
        signed=False, host_normally_injected=True,
        has_cpu_anomaly=True,  # corroborating anomaly
    )
    sigs = score_dll_load(ctx, rep)
    kinds = {sig.kind for sig in sigs}
    assert "dll_unsigned" in kinds


def test_weak_dll_signals_only_never_responds_even_over_threshold():
    # Force threshold low so weak DLL signals can cross it numerically, then
    # confirm should_respond still refuses without a non-DLL or reflective signal.
    rep = DllReputationCache()
    s = Scorer(threshold=50.0)  # cross_process 25 + abnormal 15 + unsigned 10 = 50
    ctx = DllLoadContext(
        dll_hash="abc", loader_pid=100, target_pid=200,
        signed=False, host_normally_injected=False,
        has_cpu_anomaly=False, has_network_anomaly=False,
    )
    for sig in score_dll_load(ctx, rep):
        s.add_signal(sig)
    assert s.get("pid:200").total >= 50.0
    assert s.crosses_threshold("pid:200")
    assert not s.should_respond("pid:200")  # weak-DLL-only -> never respond


def test_reputation_cache_stops_contribution_after_many_clean_loads():
    rep = DllReputationCache(clean_threshold=3)
    ctx = DllLoadContext(dll_hash="trusted123", loader_pid=1, target_pid=1, signed=True)
    for _ in range(3):
        score_dll_load(ctx, rep)  # self-load records clean loads
    assert rep.is_reputable("hash:trusted123")
    # A subsequent cross-process load of the now-reputable DLL contributes nothing.
    ctx2 = DllLoadContext(dll_hash="trusted123", loader_pid=1, target_pid=2, signed=True)
    assert score_dll_load(ctx2, rep) == []


def test_publisher_allowlist_is_surgical():
    rep = DllReputationCache()
    ctx = DllLoadContext(
        dll_hash="abc", publisher="Discord Inc.",
        loader_pid=100, target_pid=200, signed=True,
    )
    sigs = score_dll_load(ctx, rep, trusted_publishers={"Discord Inc."})
    assert sigs == []


def test_hash_allowlist_is_surgical():
    rep = DllReputationCache()
    ctx = DllLoadContext(
        dll_hash="goodhash", loader_pid=100, target_pid=200, signed=True,
    )
    sigs = score_dll_load(ctx, rep, trusted_hashes={"goodhash"})
    assert sigs == []


def test_same_publisher_not_allowlisted_still_scores():
    rep = DllReputationCache()
    ctx = DllLoadContext(
        dll_hash="abc", publisher="NotTrusted", loader_pid=100, target_pid=200,
        signed=True,
    )
    sigs = score_dll_load(ctx, rep, trusted_publishers={"Discord Inc."})
    assert any(sig.kind == "dll_cross_process" for sig in sigs)


# --------------------------------------------------------------------------- #
# Signal weight override & observability
# --------------------------------------------------------------------------- #
def test_signal_weight_override():
    s = Signal(kind="cpu_sustained", subject="x", reason="r", weight=99.0)
    assert s.effective_weight == 99.0


def test_unknown_kind_zero_weight():
    s = Signal(kind="nonexistent", subject="x", reason="r")
    assert s.effective_weight == 0.0


def test_top_reasons_populated():
    s = Scorer()
    s.add_signal(Signal(kind="cpu_sustained", subject="pid:1", reason="high cpu"))
    reasons = s.get("pid:1").top_reasons
    assert any("cpu_sustained" in r for r in reasons)


def test_reset_single_subject():
    s = Scorer()
    s.add_signal(Signal(kind="cpu_sustained", subject="pid:1", reason="r"))
    s.add_signal(Signal(kind="cpu_sustained", subject="pid:2", reason="r"))
    s.reset("pid:1")
    assert s.get("pid:1") is None
    assert s.get("pid:2") is not None
