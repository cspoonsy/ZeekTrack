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
        device = await BleakScanner.find_device_by_filter(
            lambda d, _adv: name in (d.name or ""),
            timeout=_SCAN_TIMEOUT_S,
        )
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
        stop_failed: Exception | None = None
        try:
            await self._raw_write(start_frame)
            await asyncio.sleep(duration_ms / 1000)
        finally:
            try:
                await self._raw_write(stop_frame)
            except Exception as e:
                log.warning("[%s] stop write failed: %s", self.switch_id, e)
                stop_failed = e
        if stop_failed is not None:
            raise stop_failed

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
