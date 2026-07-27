# Track-switch BLE + MQTT Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a BLE-controlled track switch (Circuit Cubes Bluetooth Bit) exposed as MQTT commands on `choochoo/switch/<id>/cmd/throw`, with a client-side burst timer and cooldown that make it impossible for any caller (or attacker) to hold the switch motor powered.

**Architecture:** New `src/choochoo/switch/` package parallels `src/choochoo/train/` — a `SwitchClient` ABC (Fake + CircuitCube backends) with a single `throw(direction)` method that runs a fixed-duration burst and always writes the stop frame in `finally`. New `switch_controller.py` mirrors `controller.py` and subscribes to switch topics. New `switch_protocol.py` holds topics, Pydantic models, and hard-coded safety constants. CLI gets `switch-controller` + `switch-send throw` subcommands. Baseline defaults to `FakeSwitch` so nothing touches BLE unless opted in.

**Tech Stack:** Python 3.14, uv, paho-mqtt 2, Pydantic v2, click, bleak (already declared under the `pi` extra), pytest, ruff.

## Global Constraints

- Design spec: `docs/superpowers/specs/2026-07-27-track-switch-ble-design.md` — treat as authoritative for anything not spelled out here.
- Reuse `choochoo.protocol.Direction` (values `"forward"` / `"reverse"`); do not introduce a second Direction enum.
- Reuse `choochoo.mqtt_auth.configure()` / `default_port()` / `publish_auth()` / `publish_tls()` for MQTT auth+TLS.
- BLE code must not import at module top level — mirror `choochoo.train.buwizz`'s pattern of importing `bleak` inside `_async_connect()` so tests can run without the `pi` extra installed.
- No new host ports; no changes to existing tests, existing train code, or existing controller.
- Ruff config (`pyproject.toml` `[tool.ruff]`): line length 100, target `py314`, lints `E F I UP B SIM`. Every new file must pass `uv run ruff check`.
- Tests must not require real BLE. `bleak` is monkey-patched.
- Do not modify `MAX_POWER`, `Direction`, or any existing symbol in `protocol.py`. Add new symbols in `switch_protocol.py`.
- The Circuit Cube has no documented watchdog. The client is the only thing stopping the motor. Every code path that starts the motor must guarantee a stop write.

---

## File Structure

**New files:**
- `src/choochoo/switch/__init__.py` — factory + re-exports
- `src/choochoo/switch/base.py` — `SwitchClient` ABC
- `src/choochoo/switch/fake.py` — `FakeSwitch`
- `src/choochoo/switch/circuit_cube.py` — `CircuitCubeSwitch` (BLE)
- `src/choochoo/switch_protocol.py` — topics, Pydantic models, safety constants
- `src/choochoo/switch_controller.py` — MQTT ↔ SwitchClient bridge
- `tests/test_switch_protocol.py`
- `tests/test_switch_fake.py`
- `tests/test_switch_controller.py`
- `tests/test_switch_circuit_cube.py`

**Modified files:**
- `src/choochoo/cli.py` — add `switch-controller`, `switch-send` subcommands
- `docker-compose.fake.yml` — add `switch-controller-fake` service under `mqtt` profile
- `README.md` — new "Track switch" subsection, env-var table entries
- `VULNERABILITIES.md` — new Part 3 with S1 entry

**Untouched:** everything in `src/choochoo/train/`, `controller.py`, `modbus_*.py`, `web.py`, `protocol.py`, `mqtt_auth.py`, existing tests, `docker-compose.real.yml`, `docker-compose.hardened.yml`, `docker-compose.yml`.

---

## Task 1: Switch protocol module (topics, models, safety constants)

**Files:**
- Create: `src/choochoo/switch_protocol.py`
- Test: `tests/test_switch_protocol.py`

**Interfaces produced (later tasks consume these):**
- Constants: `SWITCH_BURST_MS: int = 400`, `SWITCH_POWER: int = 60`, `SWITCH_COOLDOWN_S: float = 2.0`, `SWITCH_MAX_BURST_MS: int = 800`, `SWITCH_TOPIC_ROOT: str = "choochoo/switch"`
- Functions: `switch_cmd_topic(switch_id: str, action: str) -> str`, `switch_cmd_wildcard(switch_id: str) -> str`, `switch_state_topic(switch_id: str) -> str`, `switch_event_topic(switch_id: str) -> str`, `switch_discovery_topic(switch_id: str) -> str`
- Models: `ThrowCommand`, `ThrowOutcome` (StrEnum), `ThrowEvent`, `SwitchState`, `SwitchDiscovery`

**Consumes:** `choochoo.protocol.Direction`.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_switch_protocol.py`:

```python
"""Wire-format tests for the switch protocol."""

from __future__ import annotations

import pytest

from choochoo.protocol import Direction
from choochoo.switch_protocol import (
    SWITCH_BURST_MS,
    SWITCH_COOLDOWN_S,
    SWITCH_MAX_BURST_MS,
    SWITCH_POWER,
    SwitchDiscovery,
    SwitchState,
    ThrowCommand,
    ThrowEvent,
    ThrowOutcome,
    switch_cmd_topic,
    switch_cmd_wildcard,
    switch_discovery_topic,
    switch_event_topic,
    switch_state_topic,
)


def test_topic_helpers():
    assert switch_cmd_topic("sw1", "throw") == "choochoo/switch/sw1/cmd/throw"
    assert switch_cmd_wildcard("sw1") == "choochoo/switch/sw1/cmd/+"
    assert switch_state_topic("sw1") == "choochoo/switch/sw1/state"
    assert switch_event_topic("sw1") == "choochoo/switch/sw1/event"
    assert switch_discovery_topic("sw1") == "choochoo/switch/sw1/discovery"


def test_throw_command_roundtrip():
    cmd = ThrowCommand(direction=Direction.FORWARD)
    payload = cmd.model_dump_json()
    parsed = ThrowCommand.model_validate_json(payload)
    assert parsed.action == "throw"
    assert parsed.direction is Direction.FORWARD


def test_throw_command_rejects_bad_direction():
    with pytest.raises(Exception):
        ThrowCommand.model_validate({"action": "throw", "direction": "sideways"})


def test_throw_event_carries_outcome():
    ev = ThrowEvent(
        switch_id="sw1",
        direction=Direction.REVERSE,
        outcome=ThrowOutcome.COOLDOWN_REJECTED,
        ts=1234.5,
    )
    parsed = ThrowEvent.model_validate_json(ev.model_dump_json())
    assert parsed.outcome is ThrowOutcome.COOLDOWN_REJECTED
    assert parsed.ts == 1234.5


def test_switch_state_defaults():
    s = SwitchState(switch_id="sw1")
    assert s.position == "unknown"
    assert s.connected is False
    assert s.last_throw_ts is None
    assert s.cooldown_until_ts is None


def test_switch_discovery_carries_max_burst():
    d = SwitchDiscovery(
        switch_id="sw1",
        cmd_topic="choochoo/switch/sw1/cmd/+",
        state_topic="choochoo/switch/sw1/state",
    )
    assert d.max_burst_ms == SWITCH_MAX_BURST_MS
    assert d.online is True


def test_safety_constants_invariants():
    assert 0 < SWITCH_BURST_MS <= SWITCH_MAX_BURST_MS
    assert 0 < SWITCH_POWER <= 255
    assert SWITCH_COOLDOWN_S > 0
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_switch_protocol.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'choochoo.switch_protocol'`.

- [ ] **Step 3: Implement the module**

Create `src/choochoo/switch_protocol.py`:

```python
"""Wire protocol for the BLE track switch.

The switch has its own topic tree, its own retained discovery beacon, and
its own hard-coded safety envelope. The envelope constants live here so
every consumer (client, controller, tests) refers to the same values.

Baseline security posture matches the train (see V1 in VULNERABILITIES.md):
anonymous MQTT, plaintext. Motor-burnout safety is a *client-side* concern,
not a security one — the constants below are what stops a spamming
publisher from cooking the motor.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, Field

from choochoo.protocol import Direction

SWITCH_TOPIC_ROOT = "choochoo/switch"

# --- Safety envelope --------------------------------------------------------
# Hard-coded. Tune SWITCH_POWER after the first motor-connected test; the
# Circuit Cubes community deadband is ~80 but our motor is geared down.
SWITCH_BURST_MS = 400
SWITCH_POWER = 60
SWITCH_COOLDOWN_S = 2.0
# Hard ceiling. SwitchClient.throw() clamps any duration_ms argument to this
# value regardless of caller — defense in depth against a bug raising the
# nominal SWITCH_BURST_MS above what the mechanism tolerates.
SWITCH_MAX_BURST_MS = 800


def switch_cmd_topic(switch_id: str, action: str) -> str:
    return f"{SWITCH_TOPIC_ROOT}/{switch_id}/cmd/{action}"


def switch_cmd_wildcard(switch_id: str) -> str:
    return f"{SWITCH_TOPIC_ROOT}/{switch_id}/cmd/+"


def switch_state_topic(switch_id: str) -> str:
    return f"{SWITCH_TOPIC_ROOT}/{switch_id}/state"


def switch_event_topic(switch_id: str) -> str:
    return f"{SWITCH_TOPIC_ROOT}/{switch_id}/event"


def switch_discovery_topic(switch_id: str) -> str:
    return f"{SWITCH_TOPIC_ROOT}/{switch_id}/discovery"


class ThrowOutcome(StrEnum):
    OK = "ok"
    COOLDOWN_REJECTED = "cooldown_rejected"
    BLE_ERROR = "ble_error"


class ThrowCommand(BaseModel):
    action: Literal["throw"] = "throw"
    direction: Direction


class ThrowEvent(BaseModel):
    switch_id: str
    direction: Direction
    outcome: ThrowOutcome
    ts: float


SwitchPosition = Literal["forward", "reverse", "unknown"]


class SwitchState(BaseModel):
    switch_id: str
    position: SwitchPosition = "unknown"
    connected: bool = False
    last_throw_ts: float | None = None
    cooldown_until_ts: float | None = None


class SwitchDiscovery(BaseModel):
    switch_id: str
    name: str = "Circuit Cubes Track Switch"
    firmware: str = "choochoo 0.1.0"
    capabilities: list[str] = Field(default_factory=lambda: ["throw"])
    cmd_topic: str
    state_topic: str
    max_burst_ms: int = SWITCH_MAX_BURST_MS
    cooldown_s: float = SWITCH_COOLDOWN_S
    online: bool = True
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_switch_protocol.py -v`
Expected: 7 PASS.

- [ ] **Step 5: Run ruff**

Run: `uv run ruff check src/choochoo/switch_protocol.py tests/test_switch_protocol.py`
Expected: `All checks passed!`

- [ ] **Step 6: Commit**

```bash
git add src/choochoo/switch_protocol.py tests/test_switch_protocol.py
git commit -m "Add switch_protocol: topics, models, and hard-coded safety envelope"
```

---

## Task 2: `SwitchClient` ABC + `FakeSwitch` with cooldown + burst clamp

**Files:**
- Create: `src/choochoo/switch/__init__.py`
- Create: `src/choochoo/switch/base.py`
- Create: `src/choochoo/switch/fake.py`
- Test: `tests/test_switch_fake.py`

**Interfaces produced:**
- `class SwitchClient(ABC)` with `train_id`-style `switch_id: str`, methods `connect()`, `disconnect()`, `throw(direction: Direction, duration_ms: int = SWITCH_BURST_MS) -> ThrowOutcome`, `state() -> SwitchState`, `set_clock(fn: Callable[[], float]) -> None`.
- `class FakeSwitch(SwitchClient)` — logs, no BLE, uses a swappable clock for testable cooldown.
- `build_switch(kind: str, switch_id: str) -> SwitchClient` factory. Accepts `"fake"` and `"circuit_cube"` (the `"circuit_cube"` branch imports lazily so tests without the `pi` extra still work).

**Consumes:** `choochoo.protocol.Direction`, `choochoo.switch_protocol.*` (Task 1).

- [ ] **Step 1: Write the failing tests**

Create `tests/test_switch_fake.py`:

```python
"""FakeSwitch drives the cooldown + burst-clamp logic that the real BLE
backend also relies on. The real backend adds BLE I/O; the state machine
lives here and is tested here."""

from __future__ import annotations

from choochoo.protocol import Direction
from choochoo.switch import FakeSwitch
from choochoo.switch_protocol import (
    SWITCH_BURST_MS,
    SWITCH_COOLDOWN_S,
    SWITCH_MAX_BURST_MS,
    ThrowOutcome,
)


class Clock:
    def __init__(self, t: float = 1000.0) -> None:
        self.t = t

    def __call__(self) -> float:
        return self.t

    def advance(self, dt: float) -> None:
        self.t += dt


def _make(switch_id: str = "sw1") -> tuple[FakeSwitch, Clock]:
    s = FakeSwitch(switch_id)
    clk = Clock()
    s.set_clock(clk)
    s.connect()
    return s, clk


def test_connect_marks_connected():
    s, _ = _make()
    assert s.state().connected is True


def test_first_throw_succeeds_and_updates_position():
    s, _ = _make()
    outcome = s.throw(Direction.FORWARD)
    assert outcome is ThrowOutcome.OK
    st = s.state()
    assert st.position == "forward"
    assert st.last_throw_ts == 1000.0
    assert st.cooldown_until_ts == 1000.0 + SWITCH_COOLDOWN_S


def test_second_throw_inside_cooldown_is_rejected():
    s, clk = _make()
    assert s.throw(Direction.FORWARD) is ThrowOutcome.OK
    clk.advance(SWITCH_COOLDOWN_S / 2)
    outcome = s.throw(Direction.REVERSE)
    assert outcome is ThrowOutcome.COOLDOWN_REJECTED
    assert s.state().position == "forward"  # unchanged
    assert s.throws == [(Direction.FORWARD, SWITCH_BURST_MS)]  # only the first ran


def test_throw_after_cooldown_succeeds():
    s, clk = _make()
    s.throw(Direction.FORWARD)
    clk.advance(SWITCH_COOLDOWN_S + 0.01)
    outcome = s.throw(Direction.REVERSE)
    assert outcome is ThrowOutcome.OK
    assert s.state().position == "reverse"


def test_burst_duration_is_clamped_to_max():
    s, _ = _make()
    s.throw(Direction.FORWARD, duration_ms=99999)
    assert s.throws == [(Direction.FORWARD, SWITCH_MAX_BURST_MS)]


def test_disconnect_marks_disconnected():
    s, _ = _make()
    s.disconnect()
    assert s.state().connected is False


def test_factory_builds_fake():
    from choochoo.switch import build_switch

    s = build_switch("fake", "sw1")
    assert isinstance(s, FakeSwitch)


def test_factory_rejects_unknown_kind():
    from choochoo.switch import build_switch

    try:
        build_switch("bogus", "sw1")
    except ValueError:
        return
    raise AssertionError("expected ValueError for unknown kind")
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_switch_fake.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'choochoo.switch'`.

- [ ] **Step 3: Implement `SwitchClient` ABC**

Create `src/choochoo/switch/base.py`:

```python
"""Abstract switch client.

Contract:
- `throw(direction, duration_ms=SWITCH_BURST_MS)` runs the motor for a
  bounded burst and returns a `ThrowOutcome`. The client owns the timer;
  callers cannot hold the motor on.
- `duration_ms` is clamped to `SWITCH_MAX_BURST_MS` internally. It exists
  as a defensive knob for the internal caller, not the wire.
- Real backends must guarantee a stop write even if their burst task is
  cancelled or the write raises (see CircuitCubeSwitch for the pattern).
- `set_clock(fn)` swaps the wall clock the cooldown uses. Tests inject a
  fake clock; the real backend leaves the default `time.time`.
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from collections.abc import Callable

from choochoo.protocol import Direction
from choochoo.switch_protocol import (
    SWITCH_BURST_MS,
    SWITCH_COOLDOWN_S,
    SWITCH_MAX_BURST_MS,
    SwitchPosition,
    SwitchState,
    ThrowOutcome,
)


class SwitchClient(ABC):
    def __init__(self, switch_id: str) -> None:
        self.switch_id = switch_id
        self._connected = False
        self._position: SwitchPosition = "unknown"
        self._last_throw_ts: float | None = None
        self._cooldown_until_ts: float | None = None
        self._clock: Callable[[], float] = time.time

    def set_clock(self, fn: Callable[[], float]) -> None:
        self._clock = fn

    @abstractmethod
    def connect(self) -> None: ...

    @abstractmethod
    def disconnect(self) -> None: ...

    def throw(
        self,
        direction: Direction,
        duration_ms: int = SWITCH_BURST_MS,
    ) -> ThrowOutcome:
        now = self._clock()
        if self._cooldown_until_ts is not None and now < self._cooldown_until_ts:
            return ThrowOutcome.COOLDOWN_REJECTED
        clamped = min(duration_ms, SWITCH_MAX_BURST_MS)
        try:
            self._run_burst(direction, clamped)
        except Exception:
            self._last_throw_ts = now
            self._cooldown_until_ts = now + SWITCH_COOLDOWN_S
            return ThrowOutcome.BLE_ERROR
        self._position = "forward" if direction is Direction.FORWARD else "reverse"
        self._last_throw_ts = now
        self._cooldown_until_ts = now + SWITCH_COOLDOWN_S
        return ThrowOutcome.OK

    @abstractmethod
    def _run_burst(self, direction: Direction, duration_ms: int) -> None:
        """Drive the motor at SWITCH_POWER for `duration_ms`, then stop.

        Must always issue a stop write, even if the burst is interrupted."""

    def state(self) -> SwitchState:
        return SwitchState(
            switch_id=self.switch_id,
            position=self._position,
            connected=self._connected,
            last_throw_ts=self._last_throw_ts,
            cooldown_until_ts=self._cooldown_until_ts,
        )
```

- [ ] **Step 4: Implement `FakeSwitch`**

Create `src/choochoo/switch/fake.py`:

```python
from __future__ import annotations

import logging

from choochoo.protocol import Direction
from choochoo.switch.base import SwitchClient

log = logging.getLogger(__name__)


class FakeSwitch(SwitchClient):
    """In-memory switch. Records every throw so tests can assert what
    (would have) hit the wire. Uses the same cooldown/clamp logic as the
    real client via `SwitchClient.throw`."""

    def __init__(self, switch_id: str) -> None:
        super().__init__(switch_id)
        self.throws: list[tuple[Direction, int]] = []

    def connect(self) -> None:
        log.info("[%s] connect", self.switch_id)
        self._connected = True

    def disconnect(self) -> None:
        log.info("[%s] disconnect", self.switch_id)
        self._connected = False

    def _run_burst(self, direction: Direction, duration_ms: int) -> None:
        log.info("[%s] throw %s for %d ms", self.switch_id, direction, duration_ms)
        self.throws.append((direction, duration_ms))
```

- [ ] **Step 5: Implement the factory + package exports**

Create `src/choochoo/switch/__init__.py`:

```python
from choochoo.switch.base import SwitchClient
from choochoo.switch.fake import FakeSwitch

__all__ = ["SwitchClient", "FakeSwitch", "build_switch"]


def build_switch(kind: str, switch_id: str) -> SwitchClient:
    """Factory. `kind` comes from CHOOCHOO_SWITCH_KIND."""
    if kind == "fake":
        return FakeSwitch(switch_id)
    if kind == "circuit_cube":
        # Lazy import so `bleak` (from the `pi` extra) isn't required for
        # tests or the fake profile.
        from choochoo.switch.circuit_cube import CircuitCubeSwitch

        return CircuitCubeSwitch(switch_id)
    raise ValueError(f"Unknown switch kind: {kind!r}")
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `uv run pytest tests/test_switch_fake.py -v`
Expected: 8 PASS.

- [ ] **Step 7: Run ruff**

Run: `uv run ruff check src/choochoo/switch tests/test_switch_fake.py`
Expected: `All checks passed!`

- [ ] **Step 8: Commit**

```bash
git add src/choochoo/switch/ tests/test_switch_fake.py
git commit -m "Add SwitchClient ABC and FakeSwitch with cooldown + burst clamp"
```

---

## Task 3: `CircuitCubeSwitch` BLE backend (bleak monkey-patched in tests)

**Files:**
- Create: `src/choochoo/switch/circuit_cube.py`
- Test: `tests/test_switch_circuit_cube.py`

**Interfaces produced:**
- `class CircuitCubeSwitch(SwitchClient)` with the same public API. Reads `CHOOCHOO_CUBE_NAME` (default `"Tenka"`) and `CHOOCHOO_CUBE_PORT` (default `"a"`, must be one of `"a"`, `"b"`, `"c"`).
- Constants exported for testing: `NUS_SERVICE_UUID`, `NUS_WRITE_CHAR_UUID`, `NUS_NOTIFY_CHAR_UUID`.
- Module-level helper `encode_frame(direction: Direction | None, magnitude: int, port: str) -> bytes` — `direction=None` means stop; returns the 5-byte ASCII frame.

**Consumes:** everything from Task 2.

**Design notes** the implementer must not miss:
- `bleak` must be imported inside `_async_connect()`, not at module top. Same rule the existing BuWizz backend follows (`src/choochoo/train/buwizz.py:155`).
- The event loop lives on a **daemon background thread** so the synchronous `SwitchClient` API keeps working. Copy the `_start_loop` / `_stop_loop` / `_run` pattern from `src/choochoo/train/buwizz.py:271-307`.
- Burst runs entirely on the background loop as a single `_async_burst` coroutine so `try/finally` around the sleep is guaranteed to write the stop frame even if the coroutine is cancelled.
- The `SwitchClient.throw()` cooldown check has already happened before `_run_burst()` is called; the BLE backend does **not** re-check cooldown.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_switch_circuit_cube.py`:

```python
"""Exercise CircuitCubeSwitch with a fake BleakClient. No real BLE."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from choochoo.protocol import Direction
from choochoo.switch.circuit_cube import (
    NUS_WRITE_CHAR_UUID,
    CircuitCubeSwitch,
    encode_frame,
)
from choochoo.switch_protocol import (
    SWITCH_BURST_MS,
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


def test_invalid_port_env_raises(fake_bleak, monkeypatch):
    monkeypatch.setenv("CHOOCHOO_CUBE_PORT", "z")
    s = CircuitCubeSwitch("sw1")
    with pytest.raises(ValueError):
        s.connect()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_switch_circuit_cube.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'choochoo.switch.circuit_cube'`.

- [ ] **Step 3: Implement the BLE backend**

Create `src/choochoo/switch/circuit_cube.py`:

```python
"""Circuit Cubes Bluetooth Bit driver.

Community-reversed protocol (no vendor spec). Nordic UART Service; 5-byte
ASCII command frames `dNNNc` where:
- `d` = '+' or '-' (direction)
- `NNN` = zero-padded magnitude 000..255
- `c` = motor channel 'a'/'b'/'c'

Refs:
- https://github.com/repkovsky/CircuitCubesRemote
- https://github.com/made-by-simon/CircuitCubes

No documented device-side watchdog. This backend is the only thing that
can stop the motor once started — every code path that writes a start
frame guarantees a stop frame via `try/finally`.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import threading
from collections.abc import Awaitable
from typing import TypeVar

from choochoo.protocol import Direction
from choochoo.switch.base import SwitchClient
from choochoo.switch_protocol import SWITCH_BURST_MS, SWITCH_POWER

log = logging.getLogger(__name__)

T = TypeVar("T")

NUS_SERVICE_UUID = "6e400001-b5a3-f393-e0a9-e50e24dcca9e"
NUS_WRITE_CHAR_UUID = "6e400002-b5a3-f393-e0a9-e50e24dcca9e"
NUS_NOTIFY_CHAR_UUID = "6e400003-b5a3-f393-e0a9-e50e24dcca9e"

_VALID_PORTS = {"a", "b", "c"}
_DEFAULT_NAME = "Tenka"
_SCAN_TIMEOUT_S = 10.0
_CONNECT_TIMEOUT_S = 15.0


def encode_frame(direction: Direction | None, magnitude: int, port: str) -> bytes:
    """Return the 5-byte ASCII frame. `direction=None` means stop."""
    if port not in _VALID_PORTS:
        raise ValueError(f"port must be one of {sorted(_VALID_PORTS)}, got {port!r}")
    if not 0 <= magnitude <= 255:
        raise ValueError(f"magnitude must be 0..255, got {magnitude}")
    if direction is None or magnitude == 0:
        return f"+000{port}".encode("ascii")
    sign = "+" if direction is Direction.FORWARD else "-"
    return f"{sign}{magnitude:03d}{port}".encode("ascii")


class CircuitCubeSwitch(SwitchClient):
    def __init__(self, switch_id: str) -> None:
        super().__init__(switch_id)
        self._loop: asyncio.AbstractEventLoop | None = None
        self._loop_thread: threading.Thread | None = None
        self._client = None
        self._char = None
        self._port = "a"
        # Test-only hook: shortcut the 400 ms sleep so the test suite stays
        # snappy. Never set in production.
        self._burst_duration_override_ms: int | None = None

    # --- SwitchClient API --------------------------------------------------

    def connect(self) -> None:
        port = os.environ.get("CHOOCHOO_CUBE_PORT", "a")
        if port not in _VALID_PORTS:
            raise ValueError(
                f"CHOOCHOO_CUBE_PORT must be one of {sorted(_VALID_PORTS)}, got {port!r}"
            )
        self._port = port
        self._start_loop()
        self._run(self._async_connect())
        self._connected = True

    def disconnect(self) -> None:
        if self._loop is None:
            return
        try:
            self._run(self._async_disconnect())
        finally:
            self._stop_loop()
            self._connected = False

    def _run_burst(self, direction: Direction, duration_ms: int) -> None:
        effective = self._burst_duration_override_ms
        if effective is None:
            effective = duration_ms if duration_ms > 0 else SWITCH_BURST_MS
        self._run(self._async_burst(direction, effective))

    # --- async internals ---------------------------------------------------

    async def _async_connect(self) -> None:
        from bleak import BleakClient, BleakScanner

        name = os.environ.get("CHOOCHOO_CUBE_NAME", _DEFAULT_NAME)
        log.info("[%s] scanning for Circuit Cube %r over BLE...", self.switch_id, name)
        device = await BleakScanner.find_device_by_name(name, timeout=_SCAN_TIMEOUT_S)
        if device is None:
            raise RuntimeError(
                f"No BLE device named {name!r} found within {_SCAN_TIMEOUT_S:.0f}s. "
                "Is the Circuit Cube powered on? Override the name via "
                "CHOOCHOO_CUBE_NAME (substring match against the advertised name)."
            )

        client = BleakClient(device, timeout=_CONNECT_TIMEOUT_S)
        await client.connect()
        log.info("[%s] connected to Cube at %s", self.switch_id, device.address)

        char = self._find_write_characteristic(client)
        if char is None:
            await client.disconnect()
            raise RuntimeError(
                f"Could not locate NUS write characteristic {NUS_WRITE_CHAR_UUID} "
                f"under service {NUS_SERVICE_UUID}."
            )
        self._client = client
        self._char = char

    async def _async_disconnect(self) -> None:
        if self._client is None:
            return
        # Best-effort stop before dropping BLE.
        with contextlib.suppress(Exception):
            await self._raw_write(encode_frame(None, 0, self._port))
        try:
            await self._client.disconnect()
        finally:
            self._client = None
            self._char = None

    async def _async_burst(self, direction: Direction, duration_ms: int) -> None:
        start_frame = encode_frame(direction, SWITCH_POWER, self._port)
        stop_frame = encode_frame(None, 0, self._port)
        try:
            await self._raw_write(start_frame)
            await asyncio.sleep(duration_ms / 1000)
        finally:
            # Always attempt the stop write, even if the start raised or the
            # sleep was cancelled. Suppress the stop-write exception so the
            # original error (if any) surfaces via the caller.
            with contextlib.suppress(Exception):
                await self._raw_write(stop_frame)

    async def _raw_write(self, frame: bytes) -> None:
        if self._client is None or self._char is None:
            raise RuntimeError("CircuitCube not connected")
        await self._client.write_gatt_char(self._char, frame, response=False)

    @staticmethod
    def _find_write_characteristic(client) -> object | None:
        for service in client.services:
            for char in service.characteristics:
                if char.uuid.lower() == NUS_WRITE_CHAR_UUID:
                    return char
        return None

    # --- background-loop plumbing (mirrors BuWizz) -------------------------

    def _start_loop(self) -> None:
        if self._loop is not None:
            return
        ready = threading.Event()

        def runner() -> None:
            loop = asyncio.new_event_loop()
            self._loop = loop
            asyncio.set_event_loop(loop)
            ready.set()
            try:
                loop.run_forever()
            finally:
                loop.close()

        self._loop_thread = threading.Thread(
            target=runner, name=f"circuit-cube-{self.switch_id}", daemon=True
        )
        self._loop_thread.start()
        ready.wait()

    def _stop_loop(self) -> None:
        if self._loop is None:
            return
        loop = self._loop
        loop.call_soon_threadsafe(loop.stop)
        if self._loop_thread is not None:
            self._loop_thread.join(timeout=5.0)
        self._loop = None
        self._loop_thread = None

    def _run(self, coro: Awaitable[T]) -> T:
        if self._loop is None:
            raise RuntimeError("event loop not running")
        return asyncio.run_coroutine_threadsafe(coro, self._loop).result()
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_switch_circuit_cube.py -v`
Expected: 11 PASS.

- [ ] **Step 5: Run the full switch test suite to catch regressions**

Run: `uv run pytest tests/test_switch_protocol.py tests/test_switch_fake.py tests/test_switch_circuit_cube.py -v`
Expected: all PASS.

- [ ] **Step 6: Run ruff**

Run: `uv run ruff check src/choochoo/switch/circuit_cube.py tests/test_switch_circuit_cube.py`
Expected: `All checks passed!`

- [ ] **Step 7: Commit**

```bash
git add src/choochoo/switch/circuit_cube.py tests/test_switch_circuit_cube.py
git commit -m "Add CircuitCubeSwitch BLE backend with guaranteed stop-in-finally"
```

---

## Task 4: `SwitchController` — MQTT bridge, discovery, LWT, events

**Files:**
- Create: `src/choochoo/switch_controller.py`
- Test: `tests/test_switch_controller.py`

**Interfaces produced:**
- `class SwitchControllerConfig` — `broker_host: str`, `broker_port: int`, `switch_id: str`, `switch_kind: str`. Same shape as `ControllerConfig`.
- `class SwitchController` with `run()`, `_on_connect`, `_on_message`, `_publish_state`, `_publish_discovery`, `_publish_event`, `_shutdown`.

**Consumes:**
- `choochoo.mqtt_auth.configure`
- `choochoo.switch.build_switch`, `SwitchClient`
- `choochoo.switch_protocol.*`
- `choochoo.protocol.Direction`

- [ ] **Step 1: Write the failing tests**

Create `tests/test_switch_controller.py`:

```python
"""Controller tests that exercise the message handler without a real broker."""

from __future__ import annotations

import json
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from choochoo.switch_controller import SwitchController, SwitchControllerConfig
from choochoo.switch_protocol import (
    SWITCH_COOLDOWN_S,
    ThrowOutcome,
    switch_cmd_topic,
    switch_event_topic,
)


class Clock:
    def __init__(self, t: float = 1000.0) -> None:
        self.t = t

    def __call__(self) -> float:
        return self.t

    def advance(self, dt: float) -> None:
        self.t += dt


@pytest.fixture
def controller() -> tuple[SwitchController, Clock]:
    c = SwitchController(SwitchControllerConfig(switch_id="sw1", switch_kind="fake"))
    c.client = MagicMock()
    clk = Clock()
    c.switch.set_clock(clk)
    c._clock = clk  # controller uses same clock for event timestamps
    c.switch.connect()
    return c, clk


def _msg(topic: str, payload: dict):
    return SimpleNamespace(topic=topic, payload=json.dumps(payload).encode())


def _published_events(client: MagicMock, switch_id: str) -> list[dict]:
    """Return only the payloads paho.publish() saw on the event topic."""
    topic = switch_event_topic(switch_id)
    out: list[dict] = []
    for call in client.publish.call_args_list:
        args, kwargs = call
        # paho publish signature: publish(topic, payload, qos=0, retain=False)
        t = args[0] if args else kwargs.get("topic")
        if t == topic:
            payload = args[1] if len(args) > 1 else kwargs.get("payload")
            out.append(json.loads(payload))
    return out


def test_throw_command_drives_switch(controller):
    c, _ = controller
    c._on_message(None, None, _msg(switch_cmd_topic("sw1", "throw"),
                                    {"action": "throw", "direction": "forward"}))
    assert c.switch.throws  # FakeSwitch recorded the throw
    events = _published_events(c.client, "sw1")
    assert events[-1]["outcome"] == ThrowOutcome.OK.value


def test_bad_direction_is_ignored(controller):
    c, _ = controller
    c._on_message(None, None, _msg(switch_cmd_topic("sw1", "throw"),
                                    {"action": "throw", "direction": "sideways"}))
    assert c.switch.throws == []
    assert _published_events(c.client, "sw1") == []


def test_non_json_payload_is_ignored(controller):
    c, _ = controller
    msg = SimpleNamespace(topic=switch_cmd_topic("sw1", "throw"), payload=b"not json")
    c._on_message(None, None, msg)
    assert c.switch.throws == []


def test_unknown_action_is_ignored(controller):
    c, _ = controller
    c._on_message(None, None, _msg(switch_cmd_topic("sw1", "selfdestruct"), {}))
    assert c.switch.throws == []


def test_cooldown_rejection_publishes_event(controller):
    c, clk = controller
    c._on_message(None, None, _msg(switch_cmd_topic("sw1", "throw"),
                                    {"action": "throw", "direction": "forward"}))
    clk.advance(SWITCH_COOLDOWN_S / 2)  # still inside cooldown
    c._on_message(None, None, _msg(switch_cmd_topic("sw1", "throw"),
                                    {"action": "throw", "direction": "reverse"}))
    assert len(c.switch.throws) == 1
    events = _published_events(c.client, "sw1")
    outcomes = [e["outcome"] for e in events]
    assert outcomes == [ThrowOutcome.OK.value, ThrowOutcome.COOLDOWN_REJECTED.value]


def test_shutdown_disconnects_switch_and_client():
    c = SwitchController(SwitchControllerConfig(switch_id="sw1", switch_kind="fake"))
    c.client = MagicMock()
    c.switch.connect()
    c._shutdown()
    assert c.switch.state().connected is False
    c.client.disconnect.assert_called_once()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_switch_controller.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'choochoo.switch_controller'`.

- [ ] **Step 3: Implement the controller**

Create `src/choochoo/switch_controller.py`:

```python
"""Subscribes to MQTT switch-command topics and drives a SwitchClient.

Mirrors `choochoo.controller.Controller` for the train: same shutdown
discipline, same LWT + retained-discovery beacon, same "log + ignore" policy
on malformed payloads. All hardware safety (bounded burst, cooldown, stop
in finally) lives in SwitchClient — this class just wires MQTT to it.
"""

from __future__ import annotations

import json
import logging
import signal
import time
from dataclasses import dataclass

import paho.mqtt.client as mqtt
from pydantic import ValidationError

from choochoo import mqtt_auth
from choochoo.switch import SwitchClient, build_switch
from choochoo.switch_protocol import (
    SwitchDiscovery,
    SwitchState,
    ThrowCommand,
    ThrowEvent,
    ThrowOutcome,
    switch_cmd_topic,
    switch_cmd_wildcard,
    switch_discovery_topic,
    switch_event_topic,
    switch_state_topic,
)

log = logging.getLogger(__name__)


@dataclass
class SwitchControllerConfig:
    broker_host: str = "localhost"
    broker_port: int = 1883
    switch_id: str = "sw1"
    switch_kind: str = "fake"


class SwitchController:
    def __init__(self, cfg: SwitchControllerConfig) -> None:
        self.cfg = cfg
        self.switch: SwitchClient = build_switch(cfg.switch_kind, cfg.switch_id)
        self.client = mqtt.Client(
            mqtt.CallbackAPIVersion.VERSION2,
            client_id=f"choochoo-switch-controller-{cfg.switch_id}",
        )
        mqtt_auth.configure(self.client)
        self.client.on_connect = self._on_connect
        self.client.on_message = self._on_message
        # Event-timestamp clock (swapped in tests).
        self._clock = time.time

        offline = SwitchDiscovery(
            switch_id=cfg.switch_id,
            cmd_topic=switch_cmd_topic(cfg.switch_id, "+"),
            state_topic=switch_state_topic(cfg.switch_id),
            online=False,
        )
        self.client.will_set(
            switch_discovery_topic(cfg.switch_id),
            offline.model_dump_json(),
            qos=1,
            retain=True,
        )

    def run(self) -> None:
        self.switch.connect()
        self._publish_state()
        self.client.connect(self.cfg.broker_host, self.cfg.broker_port, keepalive=30)
        signal.signal(signal.SIGINT, lambda *_: self._shutdown())
        signal.signal(signal.SIGTERM, lambda *_: self._shutdown())
        self.client.loop_forever()

    def _shutdown(self) -> None:
        log.info("shutting down")
        try:
            self.switch.disconnect()
        finally:
            self.client.disconnect()

    def _on_connect(self, client, _userdata, _flags, reason_code, _props) -> None:
        topic = switch_cmd_wildcard(self.cfg.switch_id)
        log.info("connected rc=%s, subscribing to %s", reason_code, topic)
        client.subscribe(topic)
        self._publish_discovery(online=True)

    def _publish_discovery(self, online: bool) -> None:
        ann = SwitchDiscovery(
            switch_id=self.cfg.switch_id,
            cmd_topic=switch_cmd_topic(self.cfg.switch_id, "+"),
            state_topic=switch_state_topic(self.cfg.switch_id),
            online=online,
        )
        self.client.publish(
            switch_discovery_topic(self.cfg.switch_id),
            ann.model_dump_json(),
            qos=1,
            retain=True,
        )

    def _on_message(self, _client, _userdata, msg: mqtt.MQTTMessage) -> None:
        action = msg.topic.rsplit("/", 1)[-1]
        try:
            payload = json.loads(msg.payload)
        except json.JSONDecodeError:
            log.warning("non-JSON payload on %s: %r", msg.topic, msg.payload)
            return

        if action != "throw":
            log.warning("unknown action: %s", action)
            return

        try:
            cmd = ThrowCommand.model_validate(payload)
        except ValidationError as e:
            log.warning("bad payload on %s: %s", msg.topic, e)
            return

        outcome = self.switch.throw(cmd.direction)
        self._publish_event(cmd, outcome)
        self._publish_state()

    def _publish_event(self, cmd: ThrowCommand, outcome: ThrowOutcome) -> None:
        ev = ThrowEvent(
            switch_id=self.cfg.switch_id,
            direction=cmd.direction,
            outcome=outcome,
            ts=self._clock(),
        )
        self.client.publish(
            switch_event_topic(self.cfg.switch_id),
            ev.model_dump_json(),
        )

    def _publish_state(self) -> None:
        state: SwitchState = self.switch.state()
        self.client.publish(
            switch_state_topic(self.cfg.switch_id),
            state.model_dump_json(),
            retain=True,
        )
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_switch_controller.py -v`
Expected: 6 PASS.

- [ ] **Step 5: Full test suite regression check**

Run: `uv run pytest -v`
Expected: all existing train tests plus all switch tests PASS.

- [ ] **Step 6: Run ruff**

Run: `uv run ruff check src/choochoo/switch_controller.py tests/test_switch_controller.py`
Expected: `All checks passed!`

- [ ] **Step 7: Commit**

```bash
git add src/choochoo/switch_controller.py tests/test_switch_controller.py
git commit -m "Add SwitchController: MQTT bridge with cooldown-aware event emission"
```

---

## Task 5: CLI subcommands `switch-controller` and `switch-send throw`

**Files:**
- Modify: `src/choochoo/cli.py`

**Interfaces produced:** two new click subcommands wired into `main`:
- `uv run choochoo switch-controller` — reads `CHOOCHOO_SWITCH_ID` / `CHOOCHOO_SWITCH_KIND` / `CHOOCHOO_BROKER` / `CHOOCHOO_BROKER_PORT`, instantiates `SwitchController`.
- `uv run choochoo switch-send throw <direction>` — publishes a `ThrowCommand` to `choochoo/switch/<id>/cmd/throw` via `paho.mqtt.publish.single`, using the same `mqtt_auth` helpers as the existing `send` group.

**Consumes:** everything from Tasks 1–4, plus `choochoo.mqtt_auth`, `choochoo.protocol.Direction`.

- [ ] **Step 1: Add a tiny CLI smoke test**

Append to a new file `tests/test_switch_cli.py`:

```python
"""Very light CLI wiring test — invokes click without hitting a broker."""

from __future__ import annotations

from unittest.mock import patch

from click.testing import CliRunner

from choochoo.cli import main


def test_switch_send_throw_calls_publish():
    with patch("choochoo.cli.publish.single") as pub:
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["switch-send", "throw", "forward", "--switch-id", "sw1", "--host", "127.0.0.1"],
        )
        assert result.exit_code == 0, result.output
        pub.assert_called_once()
        args, kwargs = pub.call_args
        assert kwargs["hostname"] == "127.0.0.1"
        # Topic is first positional arg.
        assert args[0] == "choochoo/switch/sw1/cmd/throw"


def test_switch_controller_subcommand_is_registered():
    runner = CliRunner()
    result = runner.invoke(main, ["switch-controller", "--help"])
    assert result.exit_code == 0
    assert "switch" in result.output.lower()
```

- [ ] **Step 2: Run the smoke test to see it fail**

Run: `uv run pytest tests/test_switch_cli.py -v`
Expected: FAIL — `Error: No such command 'switch-send'` or similar.

- [ ] **Step 3: Add helper `_switch_opts` and the two subcommands to `cli.py`**

Add these imports near the top of `src/choochoo/cli.py` (leave existing imports intact):

```python
from choochoo.switch_controller import SwitchController, SwitchControllerConfig
from choochoo.switch_protocol import ThrowCommand, switch_cmd_topic
```

Add this helper *after* `_broker_opts` in `src/choochoo/cli.py`:

```python
def _switch_opts(f):
    f = click.option(
        "--switch-id",
        default=lambda: os.environ.get("CHOOCHOO_SWITCH_ID", "sw1"),
    )(f)
    return f
```

Add these subcommands *after* the existing `send_light` command:

```python
@main.command("switch-controller")
@click.option("--host", default=lambda: os.environ.get("CHOOCHOO_BROKER", "localhost"))
@click.option("--port", default=lambda: mqtt_auth.default_port(), type=int)
@_switch_opts
def switch_controller_cmd(host: str, port: int, switch_id: str) -> None:
    """Run the MQTT ↔ track-switch bridge."""
    kind = os.environ.get("CHOOCHOO_SWITCH_KIND", "fake")
    cfg = SwitchControllerConfig(
        broker_host=host, broker_port=port, switch_id=switch_id, switch_kind=kind,
    )
    SwitchController(cfg).run()


@main.group("switch-send")
def switch_send() -> None:
    """Publish a command to a switch controller."""


@switch_send.command("throw")
@click.option("--host", default=lambda: os.environ.get("CHOOCHOO_BROKER", "localhost"))
@click.option("--port", default=lambda: mqtt_auth.default_port(), type=int)
@_switch_opts
@click.argument("direction", type=click.Choice([d.value for d in Direction]))
def switch_send_throw(host: str, port: int, switch_id: str, direction: str) -> None:
    cmd = ThrowCommand(direction=Direction(direction))
    _publish(host, port, switch_cmd_topic(switch_id, "throw"), cmd.model_dump())
```

- [ ] **Step 4: Run the smoke test to verify it passes**

Run: `uv run pytest tests/test_switch_cli.py -v`
Expected: 2 PASS.

- [ ] **Step 5: Full test suite regression check**

Run: `uv run pytest -v && uv run ruff check`
Expected: all PASS + ruff clean.

- [ ] **Step 6: Commit**

```bash
git add src/choochoo/cli.py tests/test_switch_cli.py
git commit -m "Wire switch-controller and switch-send CLI subcommands"
```

---

## Task 6: `docker-compose.fake.yml` — add `switch-controller-fake` service

**Files:**
- Modify: `docker-compose.fake.yml`

**Interfaces produced:** a new service under the `mqtt` profile that runs `uv run choochoo switch-controller` inside the existing image with `CHOOCHOO_SWITCH_KIND=fake`, targeting the existing `mosquitto` service.

**Consumes:** Task 5's CLI subcommand.

- [ ] **Step 1: Read the existing fake-controller service to match its shape**

Open `docker-compose.fake.yml` and find the `controller-mqtt-fake` service (the one that runs the train controller with `CHOOCHOO_TRAIN=fake`). Note its build context, image, `depends_on`, `environment` block, and `profiles`. The new switch service must:
- reuse the same image (same `build:` block or the same tag if pre-built),
- depend on `mosquitto`,
- sit in the `mqtt` profile,
- name the container `choochoo-switch-controller-fake` for consistency with the existing `choochoo-*` container naming,
- set `CHOOCHOO_BROKER=mosquitto`, `CHOOCHOO_SWITCH_KIND=fake`, `CHOOCHOO_SWITCH_ID=sw1`,
- set the command to `uv run choochoo -v switch-controller`.

- [ ] **Step 2: Add the service block**

Add this block *after* `controller-mqtt-fake` in `docker-compose.fake.yml` (adjust the `build:` reference to match whatever the existing controller service uses — either the same `build: .` or `image: choochoo:local`):

```yaml
  switch-controller-fake:
    build: .
    image: choochoo:local
    container_name: choochoo-switch-controller-fake
    profiles: ["mqtt"]
    depends_on:
      - mosquitto
    environment:
      CHOOCHOO_BROKER: mosquitto
      CHOOCHOO_SWITCH_KIND: fake
      CHOOCHOO_SWITCH_ID: sw1
    command: ["uv", "run", "choochoo", "-v", "switch-controller"]
```

If the existing train service uses `build: .` and no explicit `image:`, drop the `image:` line here too and let compose reuse the built image via the profile shape it already uses.

- [ ] **Step 3: Validate the compose file parses**

Run: `docker compose -f docker-compose.fake.yml --profile mqtt config > /dev/null`
Expected: exit 0, no YAML errors, service name `switch-controller-fake` appears in the config output when re-run without redirection.

- [ ] **Step 4: Bring the stack up and verify the switch controller connects**

Run:
```bash
docker compose -f docker-compose.fake.yml --profile mqtt up --build -d
docker logs choochoo-switch-controller-fake --tail 20
```
Expected: log line `connected rc=Success, subscribing to choochoo/switch/sw1/cmd/+`.

- [ ] **Step 5: Send a throw and verify a state update**

Run:
```bash
docker compose -f docker-compose.fake.yml --profile mqtt exec mosquitto \
  mosquitto_pub -t choochoo/switch/sw1/cmd/throw \
  -m '{"action":"throw","direction":"forward"}'
docker logs choochoo-switch-controller-fake --tail 10
```
Expected: FakeSwitch log line `[sw1] throw Direction.FORWARD for 400 ms`.

- [ ] **Step 6: Tear down**

Run: `docker compose -f docker-compose.fake.yml --profile mqtt down`

- [ ] **Step 7: Commit**

```bash
git add docker-compose.fake.yml
git commit -m "Add switch-controller-fake service to docker-compose.fake.yml"
```

---

## Task 7: README + VULNERABILITIES.md updates

**Files:**
- Modify: `README.md`
- Modify: `VULNERABILITIES.md`

**Interfaces produced:** documentation only, no code.

- [ ] **Step 1: Add the "Track switch" subsection to `README.md`**

Find the "Topics" section in `README.md` (around line 599 of the current file — search for the `choochoo/train/<train_id>/cmd/motor` bullet list). Add a new "Track switch (BLE via Circuit Cubes)" subsection *after* the train topics, before "Security posture":

```markdown
### Track switch (BLE via Circuit Cubes)

A second BLE device — a Circuit Cubes Bluetooth Bit — drives a Lego
gear-rack track switch. The switch controller is a separate process that
runs alongside the train controller; both share the same broker.

Topics:

- `choochoo/switch/<switch_id>/cmd/throw` — `{"action":"throw","direction":"forward|reverse"}`
- `choochoo/switch/<switch_id>/state` — retained; current position + cooldown timestamps
- `choochoo/switch/<switch_id>/event` — per-throw outcome (`ok` / `cooldown_rejected` / `ble_error`)
- `choochoo/switch/<switch_id>/discovery` — retained; capabilities + safety envelope

**Motor safety.** The switch motor burns out if held on. The controller
enforces a bounded-burst timer (400 ms) at fixed low power, plus a 2 s
cooldown per switch. Values live as constants in `switch_protocol.py`;
tune after the first motor-connected test.

Run bare-metal alongside the train controller (BLE is host-only):

```sh
CHOOCHOO_SWITCH_KIND=circuit_cube \
CHOOCHOO_CUBE_NAME=Tenka \
CHOOCHOO_CUBE_PORT=a \
    uv run choochoo -v switch-controller
```

Ad-hoc throw from any host:

```sh
uv run choochoo switch-send throw forward
```
```

- [ ] **Step 2: Add env-var rows to the environment-variables table**

Find the "Environment variables (name → default → meaning)" table in `README.md` (the client-side block, around the `CHOOCHOO_TRAIN` row). Append four rows:

```markdown
| `CHOOCHOO_SWITCH_ID`      | `sw1`            | Track-switch identifier used in topic prefixes                     |
| `CHOOCHOO_SWITCH_KIND`    | `fake`           | Switch backend: `fake` / `circuit_cube`                            |
| `CHOOCHOO_CUBE_NAME`      | `Tenka`          | Substring match against the Circuit Cube's BLE advertised name     |
| `CHOOCHOO_CUBE_PORT`      | `a`              | Circuit Cube motor port for this switch: `a` / `b` / `c`           |
```

- [ ] **Step 3: Add Part 3 to `VULNERABILITIES.md`**

Append this block to the end of `VULNERABILITIES.md`:

```markdown
# Part 3 — Track-switch surface (MQTT)

## S1 — Anonymous throw commands drive real hardware

Baseline: same anonymous plaintext MQTT broker as V1. Anyone on the LAN
can publish to `choochoo/switch/<id>/cmd/throw` and physically move the
track under the train.

**Attacker action**

```sh
mosquitto_pub -h <broker> -t choochoo/switch/sw1/cmd/throw \
  -m '{"action":"throw","direction":"forward"}'
```

**Mitigation delta vs V1**

The switch controller's client-side cooldown (`SWITCH_COOLDOWN_S`) and
bounded burst (`SWITCH_BURST_MS`) mean an attacker cannot burn the motor
out by spamming throws — but they can still divert the train at chosen
moments. This is a *safety* mitigation, not a security mitigation.

**What Zeek sees**

Every throw is a distinct MQTT PUBLISH on
`choochoo/switch/<id>/cmd/throw`. `mqtt_publish.log` will show the source
IP in `id.orig_h`, the topic, and the JSON payload. A rapid burst of
`throw` messages against the cooldown floor is a distinctive signature:
throws arriving faster than one per 2 seconds cannot possibly all be
legitimate operator input.

**Detection hook**

```zeek
# Count PUBLISH events per source over a 10-second rolling window.
# Alert on any source exceeding one throw per 2 s.
```
```

- [ ] **Step 4: Verify no accidental code changes and the README still renders**

Run:
```bash
git diff --stat README.md VULNERABILITIES.md
grep -c 'switch-controller' README.md
```
Expected: at least one modified line each; grep hits ≥1.

- [ ] **Step 5: Commit**

```bash
git add README.md VULNERABILITIES.md
git commit -m "Document switch topics, env vars, and S1 vulnerability entry"
```

---

## Task 8: Final full-repo verification and motor-unplugged smoke plan handoff

**Files:** none modified; this is a verification-and-report task.

- [ ] **Step 1: Run the full test suite one more time**

Run: `uv run pytest -v`
Expected: all train tests, controller tests, protocol tests, and every new switch test PASS.

- [ ] **Step 2: Run ruff across the entire project**

Run: `uv run ruff check`
Expected: `All checks passed!`

- [ ] **Step 3: Verify the fake-profile compose still boots and the switch controller works end-to-end**

Run:
```bash
docker compose -f docker-compose.fake.yml --profile mqtt up --build -d
docker logs choochoo-switch-controller-fake --tail 20 | grep 'subscribing'
docker compose -f docker-compose.fake.yml --profile mqtt down
```
Expected: grep hits the subscribing line; teardown clean.

- [ ] **Step 4: Print the motor-unplugged verification steps**

Nothing to run automatically. Print or hand off the following checklist to the operator to execute against real hardware. **The motor lead must be physically disconnected from `CHOOCHOO_CUBE_PORT` for steps 1–4.**

  1. Start the controller:
     ```sh
     CHOOCHOO_SWITCH_KIND=circuit_cube \
     CHOOCHOO_CUBE_NAME=Tenka \
     CHOOCHOO_CUBE_PORT=a \
         uv run choochoo -v switch-controller
     ```
     Expect `connected to Cube at <mac-addr>` and a retained `discovery` beacon.
  2. From another shell: `uv run choochoo switch-send throw forward`. Expect log lines showing the `+060a` frame, ~400 ms pause, `+000a` frame, and an MQTT `event` with `outcome: "ok"`.
  3. Immediately repeat the throw. Expect the second one to publish `outcome: "cooldown_rejected"` and *no* BLE writes.
  4. SIGINT the controller mid-burst (start a throw, `Ctrl-C` while the 400 ms sleep is active). Expect a `+000a` stop frame in the log before shutdown completes.
  5. Only after all four pass, **reconnect the motor** and repeat step 2 once to verify direction. Then step 3 to confirm the gear rack doesn't bind on rapid throws.

If step 5 finds the geared-down motor doesn't move at all, raise `SWITCH_POWER` in `switch_protocol.py` (e.g. to 100, then 150) and repeat. Commit the tuning change separately.

- [ ] **Step 5: No commit — verification complete**

The plan ends here. If any earlier task's commit is missing, go back and complete it before declaring done.
