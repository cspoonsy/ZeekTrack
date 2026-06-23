"""Real BuWizz 3.0 / 3.0 Pro train via BLE.

The BuWizz brick speaks its own GATT protocol (not LEGO Wireless Protocol),
documented in the official BuWizz3 API PDF. We talk to it directly via
`bleak`, with a dedicated asyncio loop on a background thread so the
existing synchronous `TrainClient` interface keeps working.

Conventions for ChooChoo:
- Train motor on **port 1** (PU port). Default PU port mode is "simple PWM",
  so cmd 0x30 (Set motor data) drives it directly without any port-mode
  setup.
- Light maps to all four onboard RGB LEDs in white at the scaled brightness.
- Watchdog set to 2 s; we re-arm it on every motor write and also via a
  500 ms keepalive task that re-sends the last motor command. That keeps
  the train running through small BLE stalls without ever exceeding the
  watchdog window.

Reference: BuWizz_3.0_API_3.22 (commands 0x30 motor, 0x35 watchdog,
0x36 LEDs, 0x01 status notifications).
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import threading
from collections.abc import Awaitable
from typing import TypeVar

from choochoo.protocol import Direction, TrainState
from choochoo.train.base import TrainClient

log = logging.getLogger(__name__)

T = TypeVar("T")

# Service / characteristic from the BuWizz3 API. The service UUID is
# little-endian in the doc (93:6E:...:50:05); reversed to standard form below.
_BUWIZZ_SERVICE_UUID = "500592d1-74fb-4481-88b3-9919b1676e93"
# The "Application" characteristic — write + notify. Vendor uses the same
# 128-bit base as the service with the 16-bit short embedded. The doc lists
# the short as 0x2901; we resolve by short rather than guessing the full UUID
# so a firmware-side base change doesn't silently break us.
_APP_CHAR_SHORT = 0x2901

# Protocol constants.
_CMD_STATUS = 0x01
_CMD_SET_MOTOR = 0x30
_CMD_WATCHDOG = 0x35
_CMD_SET_LED = 0x36

_MOTOR_PORT_INDEX = 0  # port 1 -> bytes[1] in the cmd 0x30 frame (offset 0 in motor[])
_BRAKE_ALL_PORTS = 0x3F  # bits 0..5 set
# Per the API: only cmd 0x35 itself resets the watchdog timer — other writes
# don't bump it. So we keep the timeout comfortably long and re-arm via a
# dedicated keepalive task. 3 s timeout / 1 s ping = ample headroom.
_WATCHDOG_TIMEOUT_S = 3
_KEEPALIVE_INTERVAL_S = 1.0

_DEFAULT_BLE_NAME = "BuWizz3"
_SCAN_TIMEOUT_S = 10.0
_CONNECT_TIMEOUT_S = 15.0


def _power_to_int8(direction: Direction, power: int) -> int:
    """Map (direction, 0..100) to BuWizz's signed int8 motor value (-127..127)."""
    magnitude = max(0, min(100, power))
    scaled = round(magnitude * 127 / 100)
    return -scaled if direction is Direction.REVERSE else scaled


def _signed_byte(v: int) -> int:
    return v & 0xFF


class BuWizzTrain(TrainClient):
    def __init__(self, train_id: str) -> None:
        super().__init__(train_id)
        self._direction: Direction | None = None
        self._power = 0
        self._connected = False

        # asyncio plumbing.
        self._loop: asyncio.AbstractEventLoop | None = None
        self._loop_thread: threading.Thread | None = None
        self._client = None  # bleak.BleakClient
        self._char = None  # BleakGATTCharacteristic
        self._keepalive_task: asyncio.Task | None = None

    # --- TrainClient API ---------------------------------------------------

    def connect(self) -> None:
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

    def motor(self, direction: Direction, power: int) -> None:
        if self._client is None:
            raise RuntimeError("connect() first")
        signed = _power_to_int8(direction, power)
        frame = bytes([
            _CMD_SET_MOTOR,
            _signed_byte(signed) if _MOTOR_PORT_INDEX == 0 else 0,
            0, 0, 0, 0, 0,
            _BRAKE_ALL_PORTS,
            0,
        ])
        self._run(self._write(frame))
        self._direction = direction
        self._power = power

    def stop(self) -> None:
        if self._client is None:
            return
        frame = bytes([_CMD_SET_MOTOR, 0, 0, 0, 0, 0, 0, _BRAKE_ALL_PORTS, 0])
        self._run(self._write(frame))
        self._power = 0

    def light(self, brightness: int) -> None:
        if self._client is None:
            return
        # Brightness 0..10 -> white 0..255 across all four LEDs. Sending an
        # empty 0x36 (per the API) reverts to default behavior; we do that
        # for brightness 0 so the LEDs go back to indicating BLE state.
        if brightness <= 0:
            self._run(self._write(bytes([_CMD_SET_LED])))
            return
        level = max(0, min(255, round(brightness * 255 / 10)))
        rgb = [level, level, level]
        frame = bytes([_CMD_SET_LED] + rgb * 4)
        self._run(self._write(frame))

    def state(self) -> TrainState:
        return TrainState(
            train_id=self.train_id,
            direction=self._direction,
            power=self._power,
            connected=self._connected,
        )

    # --- async internals ---------------------------------------------------

    async def _async_connect(self) -> None:
        from bleak import BleakClient, BleakScanner

        name = os.environ.get("CHOOCHOO_BUWIZZ_NAME", _DEFAULT_BLE_NAME)
        log.info("[%s] scanning for BuWizz hub %r over BLE...", self.train_id, name)
        device = await BleakScanner.find_device_by_name(name, timeout=_SCAN_TIMEOUT_S)
        if device is None:
            raise RuntimeError(
                f"No BLE device named {name!r} found within {_SCAN_TIMEOUT_S:.0f}s. "
                "Is the BuWizz powered on? Override the name via CHOOCHOO_BUWIZZ_NAME."
            )

        client = BleakClient(device, timeout=_CONNECT_TIMEOUT_S)
        await client.connect()
        log.info("[%s] connected to BuWizz at %s", self.train_id, device.address)

        char = self._find_app_characteristic(client)
        if char is None:
            await client.disconnect()
            raise RuntimeError(
                "Could not locate BuWizz application characteristic "
                f"(short=0x{_APP_CHAR_SHORT:04x}) under service "
                f"{_BUWIZZ_SERVICE_UUID}."
            )

        await client.start_notify(char, self._on_notify)
        self._client = client
        self._char = char

        # Arm the device watchdog and start our keepalive task that re-sends
        # the last motor frame inside the watchdog window.
        await self._raw_write(bytes([_CMD_WATCHDOG, _WATCHDOG_TIMEOUT_S]))
        loop = asyncio.get_running_loop()
        self._keepalive_task = loop.create_task(self._keepalive_loop())

    async def _async_disconnect(self) -> None:
        if self._keepalive_task is not None:
            self._keepalive_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._keepalive_task
            self._keepalive_task = None

        if self._client is not None:
            # Best-effort stop, then drop BLE.
            try:
                await self._raw_write(
                    bytes([_CMD_SET_MOTOR, 0, 0, 0, 0, 0, 0, _BRAKE_ALL_PORTS, 0])
                )
            except Exception:
                log.debug("[%s] stop write failed during disconnect", self.train_id, exc_info=True)
            try:
                await self._client.disconnect()
            finally:
                self._client = None
                self._char = None

    async def _keepalive_loop(self) -> None:
        """Per the BuWizz API only cmd 0x35 itself resets the watchdog —
        regular motor writes do not. Re-arm it on a fixed cadence inside
        the watchdog window so the device doesn't drop the connection
        when the trainer leaves the slider sitting at 0."""
        ping = bytes([_CMD_WATCHDOG, _WATCHDOG_TIMEOUT_S])
        try:
            while True:
                await asyncio.sleep(_KEEPALIVE_INTERVAL_S)
                if self._client is None:
                    return
                try:
                    await self._raw_write(ping)
                except Exception:
                    log.warning(
                        "[%s] watchdog re-arm failed",
                        self.train_id,
                        exc_info=True,
                    )
        except asyncio.CancelledError:
            raise

    async def _write(self, frame: bytes) -> None:
        await self._raw_write(frame)

    async def _raw_write(self, frame: bytes) -> None:
        if self._client is None or self._char is None:
            raise RuntimeError("BuWizz not connected")
        # write-without-response per the API ("No response is generated").
        await self._client.write_gatt_char(self._char, frame, response=False)

    def _on_notify(self, _sender, data: bytearray) -> None:
        # Cmd 0x01 status report — most fields are uninteresting for us, but
        # battery level (byte 1 bits 3-4) and voltage (byte 2) are worth
        # logging at debug level so trainers can spot a flat battery.
        if not data or data[0] != _CMD_STATUS or len(data) < 3:
            return
        battery_level = (data[1] >> 3) & 0x03
        voltage = 9.0 + data[2] * 0.05
        log.debug(
            "[%s] BuWizz status: battery=%d voltage=%.2fV",
            self.train_id,
            battery_level,
            voltage,
        )

    @staticmethod
    def _find_app_characteristic(client) -> object | None:
        """Locate the 'Application' write+notify characteristic by short UUID
        within the BuWizz service. Returns None if not found."""
        for service in client.services:
            if service.uuid.lower() != _BUWIZZ_SERVICE_UUID:
                continue
            for char in service.characteristics:
                # bleak normalizes UUIDs to lowercase 128-bit form. The 16-bit
                # short lives in bytes 2-3 of the canonical string (chars 4-7).
                short = int(char.uuid[4:8], 16)
                if short == _APP_CHAR_SHORT and "write-without-response" in char.properties:
                    return char
        return None

    # --- background-loop plumbing -----------------------------------------

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
            target=runner, name=f"buwizz-{self.train_id}", daemon=True
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
