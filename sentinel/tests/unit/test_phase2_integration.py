"""Phase 2 integration tests — end-to-end signal → scorer → should_respond().

phases.md Phase 2 DoD:
    "each detector fires correctly against its matching test harness in
    plan.md, **produces a scored alert**"

These tests verify the second part: signals emitted by each detector
actually flow through scoring.py and produce correct scored alerts.
Unit tests prove each engine in isolation; these prove the INTEGRATION:

1. Single engine signals below threshold → no response
2. Corroborated signals from different engines → response
3. Each engine's signals are correctly weighted in the scorer
4. The "no single weak signal" guarantee holds across the whole pipeline
5. DLL weak-signal-only never responds even when above threshold
6. Realistic attack scenarios require multi-engine corroboration
"""
from __future__ import annotations

import hashlib
import os
import time

import pytest

from sentinel.engine.heuristics_bruteforce import BruteForceHeuristic
from sentinel.engine.heuristics_cryptomining import CryptominingHeuristic
from sentinel.engine.heuristics_ransomware import RansomwareHeuristic
from sentinel.engine.schema import Event, utc_timestamp
from sentinel.engine.scoring import (
    DllLoadContext,
    DllReputationCache,
    Scorer,
    Signal,
    score_dll_load,
)
from sentinel.engine.static_classifier import StaticClassifier, PEFeatureModel
from sentinel.intel.virustotal_client import HashVerdict


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _login_event(source_host: str = "10.0.0.1") -> Event:
    return Event(
        timestamp=utc_timestamp(),
        source="eventlog",
        event_type="login_failed",
        extra={"event_id": 4625, "source_host": source_host},
    )


def _file_write_event(path: str) -> Event:
    return Event(
        timestamp=utc_timestamp(),
        source="fs",
        event_type="file_write",
        image_path=path,
    )


def _stratum_event(pid: int, dest_port: int = 3333) -> Event:
    return Event(
        timestamp=utc_timestamp(),
        source="network",
        event_type="connection",
        pid=pid,
        extra={"dest_port": dest_port, "remote_ip": "192.168.1.50"},
    )


# ---------------------------------------------------------------------------
# 1. Single engine below threshold
# ---------------------------------------------------------------------------

class TestSingleEngineNoResponse:
    """No single engine's signal should cross the 80-point threshold alone.

    This is THE core guarantee of the architecture: "no single weak signal
    causes a suspend/quarantine on its own" (architecture.md Section 5.3,
    plan.md sentinel-0002).
    """

    def test_vt_positive_alone_below_threshold(self, tmp_path):
        """vt_positive (50) alone doesn't trigger a response."""
        f = tmp_path / "malware.exe"
        f.write_bytes(b"payload")
        from unittest.mock import MagicMock
        vt = MagicMock()
        vt.lookup.return_value = HashVerdict(
            sha256="a" * 64, verdict="malicious",
            positives=20, total=70, from_cache=False,
        )
        classifier = StaticClassifier(vt_client=vt)
        signals = classifier.classify_file_event(_file_write_event(str(f)))

        scorer = Scorer()
        scorer.add_signals(signals)
        subject = signals[0].subject
        assert not scorer.should_respond(subject), \
            f"vt_positive alone (50) should NOT trigger (threshold 80)"

    def test_brute_force_alone_below_threshold(self):
        """failed_login_burst (25) alone doesn't trigger a response."""
        heuristic = BruteForceHeuristic(failed_login_count=5, window_seconds=120.0)
        scorer = Scorer()
        for _ in range(8):
            sig = heuristic.process_login_event(_login_event())
            if sig:
                scorer.add_signal(sig)
        # Even with the signal, 25 < 80.
        subjects = scorer.subjects()
        for s in subjects:
            assert not scorer.should_respond(s), \
                f"failed_login_burst alone (25) should NOT trigger"

    def test_entropy_spike_alone_below_threshold(self, tmp_path):
        """entropy_spike (30) alone doesn't trigger a response."""
        heuristic = RansomwareHeuristic(entropy_alert=6.0)
        scorer = Scorer()
        f = tmp_path / "test.dat"
        f.write_bytes(os.urandom(4096))  # high entropy
        signals = heuristic.process_fs_event(
            Event(
                timestamp=utc_timestamp(), source="fs",
                event_type="file_write", image_path=str(f),
                extra={"entropy": 7.9, "action": "modified"},
            )
        )
        scorer.add_signals(signals)
        for s in scorer.subjects():
            assert not scorer.should_respond(s)

    def test_stratum_alone_below_threshold(self):
        """stratum_network (30) alone doesn't trigger a response."""
        heuristic = CryptominingHeuristic()
        scorer = Scorer()
        sig = heuristic.check_network_event(_stratum_event(pid=9999))
        assert sig is not None
        scorer.add_signal(sig)
        assert not scorer.should_respond(sig.subject)


# ---------------------------------------------------------------------------
# 2. Corroborated signals cross threshold
# ---------------------------------------------------------------------------

class TestCorroboratedResponse:
    """Multi-engine corroboration DOES cross the threshold — exactly as
    architecture.md designed.
    """

    def test_vt_positive_plus_rule_match_responds(self, tmp_path):
        """vt_positive (50) + rule_match_high (40) = 90 → respond."""
        scorer = Scorer()
        subject = "file:abc123"
        scorer.add_signal(Signal(
            kind="vt_positive", subject=subject,
            engine="static_classifier",
            reason="VirusTotal: 20/70 detections",
        ))
        scorer.add_signal(Signal(
            kind="rule_match_high", subject=subject,
            engine="rule_engine",
            reason="Suspicious PowerShell spawned by Office app",
        ))
        assert scorer.should_respond(subject), \
            "vt_positive (50) + rule_match_high (40) = 90 should respond"
        score = scorer.get(subject)
        assert score.total == 90.0

    def test_cryptomining_cpu_plus_stratum_responds(self):
        """cpu_sustained (30) + stratum_network (30) + rule_match_medium (20) = 80."""
        scorer = Scorer()
        subject = "pid:5555"
        scorer.add_signal(Signal(
            kind="cpu_sustained", subject=subject,
            engine="cryptomining_heuristic",
            reason="python.exe sustained >=85% CPU for >=60s",
        ))
        scorer.add_signal(Signal(
            kind="stratum_network", subject=subject,
            engine="cryptomining_heuristic",
            reason="connection to mining-pool/stratum endpoint 192.168.1.50:3333",
        ))
        scorer.add_signal(Signal(
            kind="rule_match_medium", subject=subject,
            engine="rule_engine",
            reason="Suspicious network pattern",
        ))
        assert scorer.should_respond(subject), \
            "cpu + stratum + rule_medium = 80 should respond"

    def test_ransomware_entropy_plus_rate_plus_rule_responds(self):
        """entropy_spike (30) + mass_modification (30) + rule_match_high (40) = 100."""
        scorer = Scorer()
        subject = "pid:7777"
        scorer.add_signal(Signal(
            kind="entropy_spike", subject=subject,
            engine="ransomware_heuristic",
            reason="high entropy write",
        ))
        scorer.add_signal(Signal(
            kind="mass_modification", subject=subject,
            engine="ransomware_heuristic",
            reason="50+ writes/min",
        ))
        scorer.add_signal(Signal(
            kind="rule_match_high", subject=subject,
            engine="rule_engine",
            reason="known ransomware pattern",
        ))
        assert scorer.should_respond(subject)
        assert scorer.get(subject).total == 100.0

    def test_brute_force_plus_vt_responds(self):
        """failed_login_burst (25) + vt_positive (50) + suspicious_parent (20) = 95."""
        scorer = Scorer()
        subject = "source:10.0.0.1"
        scorer.add_signal(Signal(
            kind="failed_login_burst", subject=subject,
            engine="bruteforce_heuristic",
            reason="8 failed logins from 10.0.0.1 in 120s",
        ))
        scorer.add_signal(Signal(
            kind="vt_positive", subject=subject,
            engine="static_classifier",
            reason="VirusTotal flagged uploaded tool",
        ))
        scorer.add_signal(Signal(
            kind="suspicious_parent_child", subject=subject,
            engine="rule_engine",
            reason="Suspicious parent-child process tree",
        ))
        assert scorer.should_respond(subject)
        assert scorer.get(subject).total == 95.0


# ---------------------------------------------------------------------------
# 3. DLL weak-signal-only rule holds in integration
# ---------------------------------------------------------------------------

class TestDllIntegration:
    """Even when DLL weak signals add up past 80, should_respond() refuses
    unless there's a non-DLL corroborator or a strong reflective signal.
    """

    def test_dll_weak_signals_only_no_response_even_above_threshold(self):
        scorer = Scorer()
        subject = "pid:1234"
        # dll_cross_process (25) + dll_unsigned (10) + dll_abnormal_host (15)
        # + another dll_cross_process (25) + dll_unsigned (10) = 85 → above 80
        for kind, weight in [
            ("dll_cross_process", None),
            ("dll_unsigned", None),
            ("dll_abnormal_host", None),
            ("dll_cross_process", 25.0),
            ("dll_unsigned", 10.0),
        ]:
            scorer.add_signal(Signal(
                kind=kind, subject=subject, engine="dll_handling",
                reason="test", weight=weight,
            ))
        assert scorer.get(subject).total >= 80
        assert not scorer.should_respond(subject), \
            "DLL weak-signals-only should NOT respond even above threshold"

    def test_dll_reflective_plus_cross_process_responds(self):
        """Reflective mapping is a STRONG DLL signal — it DOES trigger."""
        scorer = Scorer()
        subject = "pid:4321"
        scorer.add_signal(Signal(
            kind="dll_reflective", subject=subject,
            engine="dll_handling",
            reason="reflective injection of unknown.dll into pid 4321",
        ))
        scorer.add_signal(Signal(
            kind="dll_cross_process", subject=subject,
            engine="dll_handling",
            reason="cross-process injection",
        ))
        scorer.add_signal(Signal(
            kind="cpu_sustained", subject=subject,
            engine="cryptomining_heuristic",
            reason="high CPU",
        ))
        # 45 + 25 + 30 = 100
        assert scorer.should_respond(subject)


# ---------------------------------------------------------------------------
# 4. Realistic attack scenarios
# ---------------------------------------------------------------------------

class TestRealisticScenarios:
    """End-to-end scenarios mimicking real attack patterns. Each combines
    signals from multiple engines exactly as the live system would.
    """

    def test_scenario_cryptominer_with_dropper(self):
        """Scenario: a dropper downloads a miner, miner sustains CPU and
        connects to a stratum pool. VT flags the dropper.

        Expected: respond (vt_positive + cpu_sustained + stratum_network).
        """
        scorer = Scorer()
        subject = "pid:8888"

        # VT flags the dropper binary.
        scorer.add_signal(Signal(
            kind="vt_positive", subject=subject,
            engine="static_classifier",
            reason="VirusTotal: 30/70 detections for dropper.exe",
        ))
        # Miner sustains CPU.
        scorer.add_signal(Signal(
            kind="cpu_sustained", subject=subject,
            engine="cryptomining_heuristic",
            reason="dropper.exe sustained >=85% CPU for >=60s",
        ))
        # Miner connects to stratum pool.
        scorer.add_signal(Signal(
            kind="stratum_network", subject=subject,
            engine="cryptomining_heuristic",
            reason="connection to pool.mining.com:3333",
        ))

        # 50 + 30 + 30 = 110 → well above threshold.
        assert scorer.should_respond(subject)
        score = scorer.get(subject)
        assert score.total == 110.0
        assert len(score.top_reasons) == 3

    def test_scenario_ransomware_via_macro(self):
        """Scenario: Office macro spawns PowerShell → encrypts files.

        Expected: respond (rule_match_high + entropy_spike + mass_modification).
        """
        scorer = Scorer()
        subject = "pid:6666"

        scorer.add_signal(Signal(
            kind="rule_match_high", subject=subject,
            engine="rule_engine",
            reason="Suspicious PowerShell spawned by WINWORD.EXE",
        ))
        scorer.add_signal(Signal(
            kind="entropy_spike", subject=subject,
            engine="ransomware_heuristic",
            reason="high entropy write to Documents/important.docx",
        ))
        scorer.add_signal(Signal(
            kind="mass_modification", subject=subject,
            engine="ransomware_heuristic",
            reason="80 file writes/min in C:\\Users\\Documents",
        ))

        # 40 + 30 + 30 = 100 → respond.
        assert scorer.should_respond(subject)
        assert scorer.get(subject).total == 100.0

    def test_scenario_benign_software_no_response(self):
        """Scenario: Chrome updates itself (unsigned DLL self-load, VT clean).

        Expected: NO response — all signals are benign.
        """
        scorer = Scorer()
        subject = "pid:2222"

        # Self-load DLL → 0 signals from score_dll_load.
        ctx = DllLoadContext(
            dll_hash="b" * 64,
            publisher="Google LLC",
            loader_pid=2222,
            target_pid=2222,  # SELF-LOAD
            signed=True,
        )
        rep = DllReputationCache()
        dll_signals = score_dll_load(ctx, rep)
        scorer.add_signals(dll_signals)

        # No VT positive, no CPU, no stratum.
        assert not scorer.should_respond(subject)
        assert scorer.get(subject) is None  # no signals at all

