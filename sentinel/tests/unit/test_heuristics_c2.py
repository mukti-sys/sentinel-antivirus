"""Unit tests for heuristics_c2.py — C2 beaconing analysis and threat intel blocking."""
import time
import pytest

from sentinel.engine.heuristics_c2 import BeaconStream, C2BeaconDetector, C2Blocklist
from sentinel.engine.schema import Event, utc_timestamp


def test_beacon_stream_jitter_calculation():
    """Verify statistical mean, std_dev, and CV calculation on periodic intervals."""
    stream = BeaconStream(pid=100, remote_ip="198.51.100.1")

    # Perfectly periodic intervals (10.0s each) -> CV = 0.0
    base = 1000.0
    for i in range(5):
        stream.add_connection(base + (i * 10.0))

    metrics = stream.calculate_jitter()
    assert metrics is not None
    mean_dt, std_dt, cv = metrics
    assert round(mean_dt, 2) == 10.0
    assert round(std_dt, 4) == 0.0
    assert round(cv, 4) == 0.0

    # Irregular / bursty human browsing traffic
    human_stream = BeaconStream(pid=101, remote_ip="93.184.216.34")
    # Burst then idle: 0.2s, 0.5s, 45.0s, 1.2s
    ts = 1000.0
    for dt in [0.0, 0.2, 0.7, 45.7, 46.9]:
        human_stream.add_connection(ts + dt)

    h_metrics = human_stream.calculate_jitter()
    assert h_metrics is not None
    _, _, h_cv = h_metrics
    # Human CV is high (> 1.0)
    assert h_cv > 0.5


def test_c2_beacon_detector_triggers_on_low_jitter():
    """Verify that C2BeaconDetector emits c2_beaconing signal on periodic heartbeat."""
    detector = C2BeaconDetector(cv_threshold=0.20, cooldown_seconds=0.0)
    pid = 4455
    remote = "203.0.113.50"

    signal = None
    # Simulate 5 connections at 5.0s ± 0.1s interval (low jitter < 5%)
    cur = 1000.0
    for offset in [0.0, 5.05, 10.02, 15.08, 20.01]:
        ev = Event(
            timestamp=utc_timestamp(),
            source="network",
            event_type="connection",
            pid=pid,
            image_path=r"C:\Windows\System32\rundll32.exe",
            extra={"remote_ip": remote, "dest_port": 443},
        )
        # Use mock time
        with pytest.MonkeyPatch.context() as mp:
            mp.setattr(time, "time", lambda o=cur + offset: o)
            sig = detector.process_connection(ev)
            if sig:
                signal = sig

    assert signal is not None
    assert signal.kind == "c2_beaconing"
    assert signal.subject == f"pid:{pid}"
    assert signal.effective_weight == 40.0
    assert remote in signal.reason


def test_c2_blocklist_immediate_critical_match():
    """Verify that known C2 IP or staging port triggers c2_threat_intel signal."""
    blocklist = C2Blocklist(blocked_ips={"194.38.20.15"}, blocked_ports={50050})

    # Test IP match
    ev_ip = Event(
        timestamp=utc_timestamp(),
        source="network",
        event_type="connection",
        pid=999,
        image_path=r"C:\Malware\beacon.exe",
        extra={"remote_ip": "194.38.20.15", "dest_port": 443},
    )
    sig_ip = blocklist.check_connection(ev_ip)
    assert sig_ip is not None
    assert sig_ip.kind == "c2_threat_intel"
    assert sig_ip.effective_weight == 85.0
    assert "known C2 infrastructure IP" in sig_ip.reason

    # Test Port match (Cobalt Strike 50050)
    ev_port = Event(
        timestamp=utc_timestamp(),
        source="network",
        event_type="connection",
        pid=999,
        image_path=r"C:\Malware\beacon.exe",
        extra={"remote_ip": "45.33.32.156", "dest_port": 50050},
    )
    sig_port = blocklist.check_connection(ev_port)
    assert sig_port is not None
    assert sig_port.kind == "c2_threat_intel"
    assert sig_port.effective_weight == 85.0
    assert "port 50050" in sig_port.reason

    # Clean benign connection
    ev_clean = Event(
        timestamp=utc_timestamp(),
        source="network",
        event_type="connection",
        pid=555,
        image_path=r"C:\Program Files\App\app.exe",
        extra={"remote_ip": "142.250.190.46", "dest_port": 443},
    )
    assert blocklist.check_connection(ev_clean) is None
