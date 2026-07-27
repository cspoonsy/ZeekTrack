"""Exercise CircuitCubeSwitch with a fake BleakClient. No real BLE."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from choochoo.protocol import Direction
from choochoo.switch.circuit_cube import (
    NUS_WRITE_CHAR_UUID,
    CircuitCubeSwitch,
    encode_frame,
)
from choochoo.switch_protocol import (
    SWITCH_POWER,
    ThrowOutcome,
)

# --- pure-encoder tests ----------------------------------------------------


def test_encode_forward_magnitude_60_port_a():
    assert encode_frame(Direction.FORWARD, 60, "a") == b"+060a"


def test_encode_reverse_magnitude_60_port_b():
    assert encode_frame(Direction.REVERSE, 60, "b") == b"-060b"


def test_encode_stop_frame():
    assert encode_frame(None, 0, "a") == b"+000a"


def test_encode_magnitude_padding():
    assert encode_frame(Direction.FORWARD, 5, "c") == b"+005c"
    assert encode_frame(Direction.FORWARD, 255, "a") == b"+255a"


def test_encode_rejects_out_of_range():
    with pytest.raises(ValueError):
        encode_frame(Direction.FORWARD, 256, "a")
    with pytest.raises(ValueError):
        encode_frame(Direction.FORWARD, -1, "a")
    with pytest.raises(ValueError):
        encode_frame(Direction.FORWARD, 60, "z")


# --- BLE backend tests with a mocked BleakClient ---------------------------


class FakeBleakClient:
    def __init__(self, *_args, **_kwargs) -> None:
        self.writes: list[bytes] = []
        self.disconnected = False
        # bleak exposes services as a container of services each with a
        # `characteristics` list. We only need the write characteristic.
        char = SimpleNamespace(
            uuid=NUS_WRITE_CHAR_UUID,
            properties=["write-without-response"],
        )
        service = SimpleNamespace(uuid="6e400001-b5a3-f393-e0a9-e50e24dcca9e",
                                  characteristics=[char])
        self.services = [service]

    async def connect(self) -> None:
        pass

    async def disconnect(self) -> None:
        self.disconnected = True

    async def write_gatt_char(self, char, data, response=False) -> None:
        assert char.uuid == NUS_WRITE_CHAR_UUID
        self.writes.append(bytes(data))


@pytest.fixture
def fake_bleak(monkeypatch):
    """Monkey-patch the lazily-imported `bleak` module."""

    class FakeScanner:
        @staticmethod
        async def find_device_by_name(_name, timeout=None):
            return SimpleNamespace(address="AA:BB:CC:DD:EE:FF")

        @staticmethod
        async def find_device_by_filter(_predicate, timeout=None):
            return SimpleNamespace(address="AA:BB:CC:DD:EE:FF")

    fake_client_holder: dict[str, FakeBleakClient] = {}

    def make_client(*args, **kwargs):
        c = FakeBleakClient(*args, **kwargs)
        fake_client_holder["c"] = c
        return c

    import sys
    import types

    fake_bleak = types.ModuleType("bleak")
    fake_bleak.BleakScanner = FakeScanner
    fake_bleak.BleakClient = make_client
    monkeypatch.setitem(sys.modules, "bleak", fake_bleak)
    return fake_client_holder


def test_connect_finds_write_characteristic(fake_bleak, monkeypatch):
    monkeypatch.setenv("CHOOCHOO_CUBE_NAME", "Tenka")
    monkeypatch.setenv("CHOOCHOO_CUBE_PORT", "a")
    s = CircuitCubeSwitch("sw1")
    s.connect()
    try:
        assert s.state().connected is True
    finally:
        s.disconnect()


def test_throw_writes_start_then_stop_frames(fake_bleak, monkeypatch):
    monkeypatch.setenv("CHOOCHOO_CUBE_PORT", "a")
    s = CircuitCubeSwitch("sw1")
    # Speed up the burst so the test doesn't sleep 400 ms.
    s._burst_duration_override_ms = 20
    s.connect()
    try:
        outcome = s.throw(Direction.FORWARD)
        assert outcome is ThrowOutcome.OK
        writes = fake_bleak["c"].writes
        assert writes[0] == encode_frame(Direction.FORWARD, SWITCH_POWER, "a")
        assert writes[-1] == encode_frame(None, 0, "a")
    finally:
        s.disconnect()


def test_disconnect_writes_stop_frame(fake_bleak, monkeypatch):
    monkeypatch.setenv("CHOOCHOO_CUBE_PORT", "b")
    s = CircuitCubeSwitch("sw1")
    s.connect()
    s.disconnect()
    writes = fake_bleak["c"].writes
    # Last frame before disconnect must be a stop for port b.
    assert any(w == encode_frame(None, 0, "b") for w in writes)
    assert fake_bleak["c"].disconnected is True


def test_ble_error_during_start_still_writes_stop(fake_bleak, monkeypatch):
    """If the start write raises, the finally block must still attempt a
    stop write and the outcome must be ble_error."""
    monkeypatch.setenv("CHOOCHOO_CUBE_PORT", "a")
    s = CircuitCubeSwitch("sw1")
    s._burst_duration_override_ms = 20
    s.connect()
    try:
        # Wrap write_gatt_char to raise on the first call, then succeed.
        client = fake_bleak["c"]
        original = client.write_gatt_char
        calls = {"n": 0}

        async def flaky(char, data, response=False):
            calls["n"] += 1
            if calls["n"] == 1:
                raise RuntimeError("simulated BLE glitch")
            await original(char, data, response=response)

        client.write_gatt_char = flaky

        outcome = s.throw(Direction.FORWARD)
        assert outcome is ThrowOutcome.BLE_ERROR
        # The stop frame attempt happened (even though the first write raised).
        assert calls["n"] >= 2
    finally:
        s.disconnect()


def test_ble_error_during_stop_returns_ble_error_outcome(fake_bleak, monkeypatch):
    """If the start write succeeds but the stop write raises, throw() must
    return BLE_ERROR — otherwise the motor may still be running while the
    operator sees a clean 'ok'."""
    monkeypatch.setenv("CHOOCHOO_CUBE_PORT", "a")
    s = CircuitCubeSwitch("sw1")
    s._burst_duration_override_ms = 20
    s.connect()
    try:
        client = fake_bleak["c"]
        original = client.write_gatt_char
        calls = {"n": 0}

        async def flaky(char, data, response=False):
            calls["n"] += 1
            # First call is the start frame; second call is the stop frame
            # in the finally block — that one raises.
            if calls["n"] == 2:
                raise RuntimeError("simulated BLE glitch on stop write")
            await original(char, data, response=response)

        client.write_gatt_char = flaky

        outcome = s.throw(Direction.FORWARD)
        assert outcome is ThrowOutcome.BLE_ERROR
        assert calls["n"] == 2  # start attempted, stop attempted
    finally:
        s.disconnect()


def test_invalid_port_env_raises(fake_bleak, monkeypatch):
    monkeypatch.setenv("CHOOCHOO_CUBE_PORT", "z")
    s = CircuitCubeSwitch("sw1")
    with pytest.raises(ValueError):
        s.connect()
