"""Tests for sensors/network_sensor.py.

- Unit: snapshot/dedup logic via monkeypatched psutil (deterministic, no
  real network or admin needed).
- Live integration: open a real outbound TCP connection (to a localhost
  listener) and confirm the sensor logs a correctly-shaped `connection`
  row in events.db (Phase 1 DoD pattern for the network sensor).
"""
import socket
import time

import pytest

from sentinel.engine.event_bus import EventBus
from sentinel.sensors.network_sensor import NetworkSensor


class _FakeAddr:
    def __init__(self, ip, port):
        self.ip = ip
        self.port = port


class _FakeConn:
    def __init__(self, pid, status, laddr, raddr):
        self.pid = pid
        self.status = status
        self.laddr = laddr
        self.raddr = raddr


def _make_sensor(bus, conns, monkeypatch):
    import psutil

    monkeypatch.setattr(psutil, "net_connections", lambda kind="tcp": conns)
    return NetworkSensor(bus, poll_interval=0.05)


def test_snapshot_logs_new_outbound_connection(bus_and_conn, monkeypatch):
    bus, conns = bus_and_conn
    sensor = _make_sensor(bus, conns, monkeypatch)
    n = sensor.poll_once()
    assert n == 1
    rows = bus.recent(limit=10, where="source=?", params=("network",))
    assert len(rows) == 1
    r = rows[0]
    assert r["source"] == "network"
    assert r["event_type"] == "connection"
    e = r["extra"]
    assert e["remote_ip"] == "93.184.216.34"
    assert e["dest_port"] == 443
    assert e["status"] == "ESTABLISHED"


def test_dedup_does_not_relog_same_connection(bus_and_conn, monkeypatch):
    bus, conns = bus_and_conn
    sensor = _make_sensor(bus, conns, monkeypatch)
    sensor.poll_once()
    n2 = sensor.poll_once()  # same connection still present -> no new event
    assert n2 == 0
    assert bus.count(where="source=?", params=("network",)) == 1


def test_ignores_non_outbound_and_listening(bus_and_conn_listening, monkeypatch):
    bus, conns = bus_and_conn_listening
    sensor = _make_sensor(bus, conns, monkeypatch)
    n = sensor.poll_once()
    assert n == 0  # nothing logged


def test_access_denied_is_handled_gracefully(bus_and_conn, monkeypatch):
    bus, conns = bus_and_conn
    import psutil

    def boom(kind="tcp"):
        raise psutil.AccessDenied()

    monkeypatch.setattr(psutil, "net_connections", boom)
    sensor = NetworkSensor(bus, poll_interval=0.05)
    assert sensor.poll_once() == 0  # no crash, no events


# --------------------------------------------------------------------- #
# fixtures
# --------------------------------------------------------------------- #
@pytest.fixture()
def bus_and_conn(tmp_path):
    bus = EventBus(db_path=tmp_path / "events.db")
    conns = [
        _FakeConn(
            pid=4242,
            status="ESTABLISHED",
            laddr=_FakeAddr("192.168.1.10", 51234),
            raddr=_FakeAddr("93.184.216.34", 443),
        )
    ]
    yield bus, conns
    bus.close()


@pytest.fixture()
def bus_and_conn_listening(tmp_path):
    bus = EventBus(db_path=tmp_path / "events.db")
    conns = [
        _FakeConn(pid=0, status="LISTEN", laddr=_FakeAddr("0.0.0.0", 80), raddr=None),
        # ESTABLISHED but no remote addr -> also ignored
        _FakeConn(pid=1, status="ESTABLISHED",
                  laddr=_FakeAddr("192.168.1.10", 1), raddr=None),
    ]
    yield bus, conns
    bus.close()


def test_live_loopback_connection_is_logged(tmp_path):
    """Phase 1 DoD for the network sensor: a real outbound TCP connection
    produces a correctly-shaped `connection` row in events.db.

    Uses a localhost listener + a client socket on the same host so no
    external network or admin is required.
    """
    bus = EventBus(db_path=tmp_path / "events.db")
    # Start a local listener and connect to it.
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(("127.0.0.1", port))
    conn_sock, _ = listener.accept()

    sensor = NetworkSensor(bus, poll_interval=0.1)
    sensor.start()
    try:
        deadline = time.time() + 3
        rows = []
        while time.time() < deadline:
            rows = [
                r for r in bus.recent(limit=500, where="source=?", params=("network",))
                if r["extra"].get("remote_ip") == "127.0.0.1"
                and r["extra"].get("dest_port") == port
            ]
            if rows:
                break
            time.sleep(0.1)
    finally:
        sensor.stop()
        conn_sock.close()
        client.close()
        listener.close()
        bus.close()

    assert rows, "loopback connection was not logged"
    r = rows[0]
    assert r["event_type"] == "connection"
    assert r["extra"]["remote_ip"] == "127.0.0.1"
    assert r["extra"]["dest_port"] == port
    assert r["pid"] is not None  # this test process owns the socket
