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

# Auto-reconnect. Mirrors buwizz.py — background task tears the dead
# client down and re-runs _async_connect with exponential backoff.
_RECONNECT_INITIAL_S = 5.0
_RECONNECT_MAX_S = 30.0

# Idle GATT keepalive. The Cube has no vendor-side watchdog, but idle
# BLE links get dropped by the peripheral's LL supervision timer — seen
# on BlueZ where the connection interval is longer than macOS/CoreBluetooth
# negotiates. Sending a real GATT frame every few seconds resets it. The
# stop frame is a safe no-op when the motor is already stopped, so it
# doubles as the keepalive payload.
_KEEPALIVE_INTERVAL_S = 3.0


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
        # Cached BLE address from the first successful connect; lets the
        # reconnect task skip the 10 s scan window on Cube power-cycles.
        # Nothing in the wire protocol demands the address survives a
        # power cycle, but the TI SoC family behind the Cube keeps it.
        self._cached_address: str | None = None
        self._reconnect_task: asyncio.Task | None = None
        self._keepalive_task: asyncio.Task | None = None
        # Non-zero while a burst is running. Keepalive skips its write when
        # this is >0 so we don't stop-frame a live motor mid-throw.
        self._burst_in_flight = 0

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
        # Fast-reject on a known-dead link. The ABC catches the exception
        # and returns ThrowOutcome.BLE_ERROR — the operator sees the
        # failure on the wire, and no BLE writes are attempted.
        if not self._link_alive:
            raise RuntimeError("BLE link is not currently alive")
        effective = self._burst_duration_override_ms
        if effective is None:
            effective = duration_ms if duration_ms > 0 else SWITCH_BURST_MS
        self._run(self._async_burst(direction, effective))

    # --- async internals ---------------------------------------------------

    async def _async_connect(self) -> None:
        from bleak import BleakClient, BleakScanner

        name = os.environ.get("CHOOCHOO_CUBE_NAME", _DEFAULT_NAME)
        # Fast path — cached address survives a Cube power cycle.
        if self._cached_address is not None:
            log.info(
                "[%s] reconnecting to cached Cube address %s",
                self.switch_id, self._cached_address,
            )
            device_or_addr: object = self._cached_address
            address_for_log = self._cached_address
        else:
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
            device_or_addr = device
            address_for_log = device.address

        client = BleakClient(device_or_addr, timeout=_CONNECT_TIMEOUT_S)
        await client.connect()
        log.info("[%s] connected to Cube at %s", self.switch_id, address_for_log)

        char = self._find_write_characteristic(client)
        if char is None:
            await client.disconnect()
            raise RuntimeError(
                f"Could not locate NUS write characteristic {NUS_WRITE_CHAR_UUID} "
                f"under service {NUS_SERVICE_UUID}."
            )
        self._client = client
        self._char = char
        self._cached_address = address_for_log
        # No vendor watchdog on the Cube. Mark the link alive optimistically;
        # the keepalive loop (below) is what actually proves it every few
        # seconds by writing a real GATT frame.
        self._link_alive = True
        loop = asyncio.get_running_loop()
        self._keepalive_task = loop.create_task(self._keepalive_loop())
        if self._reconnect_task is None:
            self._reconnect_task = loop.create_task(self._reconnect_loop())

    async def _keepalive_loop(self) -> None:
        """Periodically re-send the stop frame so BlueZ / the Cube don't
        drop the link on the LL supervision timer. Suspended while a burst
        is running so we can't stop the motor mid-throw."""
        stop_frame = encode_frame(None, 0, self._port)
        try:
            while True:
                await asyncio.sleep(_KEEPALIVE_INTERVAL_S)
                if self._burst_in_flight > 0:
                    continue
                if not self._link_alive:
                    return
                try:
                    await self._raw_write(stop_frame)
                except Exception:
                    # _raw_write flipped _link_alive; the reconnect loop
                    # takes over from here.
                    return
        except asyncio.CancelledError:
            raise

    async def _reconnect_loop(self) -> None:
        """Watches `_link_alive`. When it's False, tear down the dead
        BleakClient and re-run `_async_connect` with exponential backoff.
        Runs until disconnected."""
        delay = _RECONNECT_INITIAL_S
        try:
            while True:
                await asyncio.sleep(0.25)
                if self._link_alive:
                    delay = _RECONNECT_INITIAL_S
                    continue

                if self._client is not None:
                    try:
                        await self._client.disconnect()
                    except Exception:
                        log.debug(
                            "[%s] disconnect of dead client raised",
                            self.switch_id, exc_info=True,
                        )
                    self._client = None
                    self._char = None
                if self._keepalive_task is not None:
                    self._keepalive_task.cancel()
                    with contextlib.suppress(asyncio.CancelledError):
                        await self._keepalive_task
                    self._keepalive_task = None

                log.info(
                    "[%s] BLE link dead; reconnect attempt in %.1fs",
                    self.switch_id, delay,
                )
                await asyncio.sleep(delay)
                try:
                    await self._async_connect()
                except Exception:
                    log.warning(
                        "[%s] reconnect attempt failed",
                        self.switch_id, exc_info=True,
                    )
                    delay = min(delay * 2, _RECONNECT_MAX_S)
                    # If the cached address is stale (Cube renamed
                    # between sessions), fall back to a fresh scan.
                    self._cached_address = None
                else:
                    delay = _RECONNECT_INITIAL_S
                    log.info("[%s] reconnected", self.switch_id)
        except asyncio.CancelledError:
            raise

    async def _async_disconnect(self) -> None:
        if self._reconnect_task is not None:
            self._reconnect_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._reconnect_task
            self._reconnect_task = None
        if self._keepalive_task is not None:
            self._keepalive_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._keepalive_task
            self._keepalive_task = None
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
            self._link_alive = False

    async def _async_burst(self, direction: Direction, duration_ms: int) -> None:
        start_frame = encode_frame(direction, SWITCH_POWER, self._port)
        stop_frame = encode_frame(None, 0, self._port)
        stop_failed: Exception | None = None
        self._burst_in_flight += 1
        try:
            await self._raw_write(start_frame)
            await asyncio.sleep(duration_ms / 1000)
        finally:
            try:
                await self._raw_write(stop_frame)
            except Exception as e:
                log.warning("[%s] stop write failed: %s", self.switch_id, e)
                stop_failed = e
            self._burst_in_flight -= 1
        if stop_failed is not None:
            raise stop_failed

    async def _raw_write(self, frame: bytes) -> None:
        if self._client is None or self._char is None:
            self._link_alive = False
            raise RuntimeError("CircuitCube not connected")
        try:
            await self._client.write_gatt_char(self._char, frame, response=False)
        except Exception:
            # Peer unreachable — flip the liveness flag so state() reports
            # disconnected and the reconnect task takes over. Re-raise so
            # the burst's finally block still attempts a stop frame.
            self._link_alive = False
            raise
        else:
            self._link_alive = True

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
