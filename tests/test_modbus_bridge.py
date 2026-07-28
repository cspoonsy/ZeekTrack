"""ModbusBridge liveness + reconnect.

The bridge is a Modbus master that polls the outstation over TCP. Its
pymodbus AsyncModbusTcpClient is monkey-patched with a stub that lets
each test model outstation up/down without a real listener.

We test three things:
- A successful poll caches a healthy TrainState.
- A polling failure flips the cached state to connected=false so the
  web UI reflects reality.
- After a poll failure the bridge attempts to reconnect (so a restarted
  outstation heals without operator intervention)."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest
from pymodbus.exceptions import ConnectionException

from choochoo.modbus_bridge import ModbusBridge


class _RegResult:
    def __init__(self, registers, error=False):
        self.registers = registers
        self._error = error

    def isError(self) -> bool:  # noqa: N802 — pymodbus API
        return self._error


class _BitResult:
    def __init__(self, bits, error=False):
        self.bits = bits
        self._error = error

    def isError(self) -> bool:  # noqa: N802
        return self._error


class FakeModbusClient:
    """Minimal AsyncModbusTcpClient stand-in.

    Tests toggle `alive`. When False, reads raise ConnectionException the
    same way pymodbus does when the socket is dead."""

    def __init__(self, *args, **kwargs) -> None:
        self.alive = True
        self.connect_calls = 0
        self.close_calls = 0

    async def connect(self) -> bool:
        self.connect_calls += 1
        return self.alive

    def close(self) -> None:
        self.close_calls += 1

    def _guard(self):
        if not self.alive:
            raise ConnectionException("stub: outstation down")

    async def read_input_registers(self, address, count, slave):
        self._guard()
        # IR 0 = current_power, IR 1 = MAX_POWER
        return _RegResult([0, 50])

    async def read_discrete_inputs(self, address, count, slave):
        self._guard()
        # DI 0 = connected=True, DI 1 = direction=forward, rest False
        return _BitResult([True, True, False, False, False])

    async def write_registers(self, *_args, **_kwargs):
        self._guard()
        return _RegResult([])

    async def write_coil(self, *_args, **_kwargs):
        self._guard()
        return _RegResult([])

    async def write_register(self, *_args, **_kwargs):
        self._guard()
        return _RegResult([])


def _bridge_with_client(client):
    b = ModbusBridge("test-host", 5020, "t1")
    b._client = client
    # No FastAPI loop — publishing subscribers is not exercised here.
    b._loop = None
    return b


# --- Baseline poll ---------------------------------------------------------


@pytest.mark.asyncio
async def test_poll_caches_healthy_state():
    client = FakeModbusClient()
    b = _bridge_with_client(client)
    await b._poll_once()
    assert b.state is not None
    assert b.state.connected is True


# --- Failure path ----------------------------------------------------------


@pytest.mark.asyncio
async def test_poll_failure_marks_state_disconnected():
    """When the outstation stops responding, the cached state must flip
    to connected=false so consumers see the outage."""
    client = FakeModbusClient()
    b = _bridge_with_client(client)
    # Seed a healthy state so we can prove the failure OVERWRITES it.
    await b._poll_once()
    assert b.state.connected is True
    # Outstation dies.
    client.alive = False
    await b._poll_once()
    assert b.state is not None
    assert b.state.connected is False


@pytest.mark.asyncio
async def test_poll_failure_attempts_reconnect():
    """After a failed poll the bridge must call `client.connect()` so a
    restarted outstation is picked up automatically."""
    client = FakeModbusClient()
    b = _bridge_with_client(client)
    await b._poll_once()  # seed
    baseline_connect_calls = client.connect_calls
    client.alive = False
    await b._poll_once()
    assert client.connect_calls > baseline_connect_calls, (
        "expected _poll_once to trigger a reconnect attempt after failure"
    )


@pytest.mark.asyncio
async def test_poll_recovers_after_outstation_returns():
    """A dead outstation coming back should show up on the next poll
    with connected=true."""
    client = FakeModbusClient()
    b = _bridge_with_client(client)
    client.alive = False
    await b._poll_once()  # fails, sets connected=false
    assert b.state.connected is False
    client.alive = True
    await b._poll_once()  # succeeds
    assert b.state.connected is True


# Wire the async loop into pytest-asyncio via the ini config the project
# already uses. If this file becomes the first async test in the project,
# also update pyproject.toml's asyncio_mode.
_ = MagicMock  # kept for future async fixture work
