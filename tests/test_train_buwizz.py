"""Tests for BuWizzTrain — link-alive tracking + auto-reconnect.

Bleak's BleakClient and BleakScanner are monkey-patched so no real BLE
happens. Async internals are driven via BuWizzTrain's public sync API,
which is the same surface ModbusController uses in production."""

from __future__ import annotations

import sys
import time
import types
from types import SimpleNamespace

import pytest

from choochoo.protocol import Direction
from choochoo.train.buwizz import BuWizzTrain


class FakeCharacteristic:
    def __init__(self) -> None:
        # Standard 128-bit UUID; chars 4:8 are the 16-bit short (0x2901).
        # The real BuWizz "Application" char uses the vendor service base
        # with this short embedded.
        self.uuid = "00002901-b5a3-f393-e0a9-e50e24dcca9e"
        self.properties = ["write-without-response"]


class FakeService:
    def __init__(self) -> None:
        self.uuid = "500592d1-74fb-4481-88b3-9919b1676e93"
        self.characteristics = [FakeCharacteristic()]


class FakeBleakClient:
    """Minimal in-memory BleakClient. Tests toggle `alive` to model a
    peer power-cycle: writes raise once alive=False."""

    def __init__(self, device, timeout=None) -> None:
        self.device = device
        self.services = [FakeService()]
        self.writes: list[bytes] = []
        self.notify_handler = None
        self.disconnected = False
        # In production this is a bleak property; here it's a bool the test
        # or the fake infrastructure can flip. Not consulted by the fix
        # (see buwizz.py — _link_alive is what state() reads), but present
        # for realism.
        self.is_connected = True
        self.alive = True

    async def connect(self) -> None:
        pass

    async def start_notify(self, char, cb) -> None:
        self.notify_handler = cb

    async def write_gatt_char(self, char, data, response=False) -> None:
        if not self.alive:
            raise RuntimeError("simulated BLE write failure (peer gone)")
        self.writes.append(bytes(data))

    async def disconnect(self) -> None:
        self.disconnected = True


@pytest.fixture
def fake_bleak(monkeypatch):
    """Install a fake `bleak` module with a stub scanner + client factory.

    Returns a dict with `client` (last-constructed FakeBleakClient) and
    `scan_calls` (count of BleakScanner.find_device_by_name invocations),
    so tests can assert reconnect behavior touched them."""

    made: dict = {"client": None, "scan_calls": 0}

    class FakeScanner:
        @staticmethod
        async def find_device_by_name(_name, timeout=None):
            made["scan_calls"] += 1
            return SimpleNamespace(address="AA:BB:CC:DD:EE:FF")

    def make_client(device, timeout=None):
        c = FakeBleakClient(device, timeout=timeout)
        made["client"] = c
        return c

    fake = types.ModuleType("bleak")
    fake.BleakScanner = FakeScanner
    fake.BleakClient = make_client
    monkeypatch.setitem(sys.modules, "bleak", fake)
    return made


# --- Baseline behavior -----------------------------------------------------


def test_state_reports_connected_after_connect(fake_bleak):
    t = BuWizzTrain("t1")
    t.connect()
    try:
        # The initial watchdog-arm write inside _async_connect must have
        # succeeded, so _link_alive is True.
        assert t.state().connected is True
    finally:
        t.disconnect()


def test_motor_writes_frame_on_healthy_link(fake_bleak):
    t = BuWizzTrain("t1")
    t.connect()
    try:
        t.motor(Direction.FORWARD, 40)
        # The first write is the watchdog arm (2 bytes: 0x35 + timeout).
        # The second is the motor frame; verify the first byte is 0x30.
        writes = fake_bleak["client"].writes
        motor_writes = [w for w in writes if w and w[0] == 0x30]
        assert motor_writes, f"no motor frame in writes={writes!r}"
    finally:
        t.disconnect()


# --- Live-link tracking ----------------------------------------------------


def test_state_reports_disconnected_after_write_failure(fake_bleak):
    """When the peer disappears, the next write fails and state() must
    reflect it. This is the exact regression the whole feature is for."""
    t = BuWizzTrain("t1")
    t.connect()
    try:
        assert t.state().connected is True
        fake_bleak["client"].alive = False
        with pytest.raises(RuntimeError):
            t.motor(Direction.FORWARD, 30)
        assert t.state().connected is False
    finally:
        t.disconnect()


def test_motor_raises_when_link_dead(fake_bleak):
    """Fast-reject: operator commands issued after the link is known
    dead must raise instead of silently succeeding."""
    t = BuWizzTrain("t1")
    t.connect()
    try:
        fake_bleak["client"].alive = False
        # Cause link_alive to flip via a failed write.
        with pytest.raises(RuntimeError):
            t.motor(Direction.FORWARD, 25)
        # Now the second call should raise fast without even attempting
        # the write (link_alive is already False).
        with pytest.raises(RuntimeError):
            t.motor(Direction.REVERSE, 25)
    finally:
        t.disconnect()


def test_stop_on_dead_link_is_noop_not_raise(fake_bleak):
    """`stop()` is safety-critical — an outstation dropping its safety
    hand into a dead link should NOT crash the outstation. Log + no-op
    is the right posture."""
    t = BuWizzTrain("t1")
    t.connect()
    try:
        fake_bleak["client"].alive = False
        # Trip the link.
        with pytest.raises(RuntimeError):
            t.motor(Direction.FORWARD, 25)
        # `stop()` on a dead link should return silently.
        t.stop()  # must not raise
    finally:
        t.disconnect()


# --- Auto-reconnect --------------------------------------------------------


def test_reconnect_recovers_link_after_peer_returns(fake_bleak, monkeypatch):
    """After the peer disappears and comes back, the reconnect task
    should re-establish _link_alive without operator intervention."""
    # Shorten reconnect delay so the test doesn't take 5+ seconds.
    monkeypatch.setattr("choochoo.train.buwizz._RECONNECT_INITIAL_S", 0.2)
    monkeypatch.setattr("choochoo.train.buwizz._RECONNECT_MAX_S", 0.5)

    t = BuWizzTrain("t1")
    t.connect()
    try:
        assert t.state().connected is True
        first_client = fake_bleak["client"]
        first_client.alive = False
        with pytest.raises(RuntimeError):
            t.motor(Direction.FORWARD, 25)
        assert t.state().connected is False

        # Simulate the peer coming back. The reconnect loop must build
        # a fresh client; the fixture flips its `alive=True` by default.
        # Wait long enough for at least one reconnect attempt to succeed.
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline:
            if t.state().connected:
                break
            time.sleep(0.1)
        assert t.state().connected is True, "reconnect did not restore link"
        # A fresh BleakClient must have been constructed.
        assert fake_bleak["client"] is not first_client
    finally:
        t.disconnect()
