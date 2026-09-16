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

# Onboard-LED indicator behavior. Baseline is a dim blue; every command
# received by the outstation briefly flashes red before returning to
# blue. Gives the train a visible "network activity" signal — useful in
# the training range for spotting attacker traffic vs. quiescent state.
# Values are 0..255 per channel; brightness is a percent applied uniformly
# so it's easy to tune for the room. Overridable via env for on-site
# lighting adjustments without editing code.
_IDLE_COLOR_RGB = (0, 0, 255)          # blue
_FLASH_COLOR_RGB = (255, 0, 0)         # red
_LED_BRIGHTNESS_PCT_DEFAULT = 25       # 25 % — subdued in room light
_FLASH_DURATION_S = 0.25

# Auto-reconnect. When the BLE link goes dead (see BuWizzTrain._link_alive),
# a background task tears down the dead BleakClient and re-runs the connect
# flow. Backoff starts at _RECONNECT_INITIAL_S and doubles (capped at
# _RECONNECT_MAX_S) between failures. Tests monkey-patch these to keep
# the suite fast.
_RECONNECT_INITIAL_S = 5.0
_RECONNECT_MAX_S = 30.0


def _power_to_int8(direction: Direction, power: int) -> int:
    """Map (direction, 0..100) to BuWizz's signed int8 motor value (-127..127)."""
    magnitude = max(0, min(100, power))
    scaled = round(magnitude * 127 / 100)
    return -scaled if direction is Direction.REVERSE else scaled


def _signed_byte(v: int) -> int:
    return v & 0xFF


def _build_led_frame(rgb: tuple[int, int, int], brightness_pct: int) -> bytes:
    """Build a `0x36 R G B ...` LED command scaled to brightness_pct.
    Replicates the single RGB across all four onboard LEDs."""
    scale = max(0, min(100, brightness_pct)) / 100
    scaled = [max(0, min(255, round(c * scale))) for c in rgb]
    return bytes([_CMD_SET_LED] + scaled * 4)


class BuWizzTrain(TrainClient):
    def __init__(self, train_id: str) -> None:
        super().__init__(train_id)
        self._direction: Direction | None = None
        self._power = 0
        self._connected = False
        # `_link_alive` is what `state().connected` actually reports.
        # `_raw_write` sets it True on success and False on any exception
        # (which is what happens when the peer disappears — CoreBluetooth
        # keeps `BleakClient.is_connected` True after a peer power-off
        # until it decides to notice, but writes fail immediately). So a
        # fresh watchdog ping every second doubles as a liveness probe.
        self._link_alive = False
        # Cached BLE address from the first successful connect. Lets the
        # reconnect task skip the 10 s scan window on hub power-cycles
        # (the address survives a power cycle on the BuWizz).
        self._cached_address: str | None = None

        # asyncio plumbing.
        self._loop: asyncio.AbstractEventLoop | None = None
        self._loop_thread: threading.Thread | None = None
        self._client = None  # bleak.BleakClient
        self._char = None  # BleakGATTCharacteristic
        self._keepalive_task: asyncio.Task | None = None
        self._reconnect_task: asyncio.Task | None = None

        # LED indicator state. Brightness is percentage (0..100) applied
        # uniformly across all channels; operator's light() slider scales
        # this. _flash_in_flight is a coarse re-entrancy guard so
        # back-to-back writes don't stampede overlapping flash tasks.
        try:
            self._led_brightness_pct = max(0, min(100, int(
                os.environ.get(
                    "CHOOCHOO_BUWIZZ_LED_BRIGHTNESS",
                    _LED_BRIGHTNESS_PCT_DEFAULT,
                )
            )))
        except ValueError:
            self._led_brightness_pct = _LED_BRIGHTNESS_PCT_DEFAULT
        self._flash_in_flight = False

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
        # Fast-reject on a dead link so the operator sees the failure
        # rather than a silent no-op. The reconnect task will bring the
        # link back on its own; there is no queue.
        if not self._link_alive:
            raise RuntimeError(
                "BLE link is not currently alive — command dropped. "
                "The controller will reconnect automatically.",
            )
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
        # `stop()` is safety-critical: it's called from the outstation's
        # shutdown path and from the E-stop coil. Do not raise on a dead
        # link — a raise here would crash the outstation on shutdown or
        # obscure the E-stop's intent. Log at warning level so the
        # operator can still see it.
        if self._client is None or not self._link_alive:
            log.warning(
                "[%s] stop() called with link not alive; no BLE write issued",
                self.train_id,
            )
            self._power = 0
            return
        frame = bytes([_CMD_SET_MOTOR, 0, 0, 0, 0, 0, 0, _BRAKE_ALL_PORTS, 0])
        try:
            self._run(self._write(frame))
        except Exception:
            log.warning(
                "[%s] stop() BLE write failed", self.train_id, exc_info=True,
            )
        self._power = 0

    def light(self, brightness: int) -> None:
        if self._client is None or not self._link_alive:
            # Silent drop, unlike motor(): light is cosmetic. Log at debug
            # so it doesn't spam.
            log.debug(
                "[%s] light() called with link not alive; dropped",
                self.train_id,
            )
            return
        # Operator's brightness slider (0..10) scales the idle-color
        # brightness. Empty 0x36 (per the API) reverts to default
        # firmware LED behavior — we use that for brightness 0 so the
        # LEDs revert to indicating BLE state.
        if brightness <= 0:
            self._run(self._write(bytes([_CMD_SET_LED])))
            return
        pct = max(0, min(100, round(brightness * 100 / 10)))
        self._led_brightness_pct = pct
        self._run(self._write(_build_led_frame(_IDLE_COLOR_RGB, pct)))

    def flash_indicator(self) -> None:
        """Fire-and-forget: flash the onboard LEDs red for a short window
        then revert to the idle blue. Safe to call from any thread; the
        actual GATT writes happen on the bleak asyncio loop. Coalesces
        rapid calls via _flash_in_flight so back-to-back commands don't
        stampede the BLE link."""
        if self._client is None or not self._link_alive:
            return
        if self._flash_in_flight:
            return
        if self._loop is None:
            return
        # Schedule without awaiting — this is fire-and-forget from the
        # caller's perspective.
        asyncio.run_coroutine_threadsafe(self._flash_indicator(), self._loop)

    async def _flash_indicator(self) -> None:
        self._flash_in_flight = True
        try:
            with contextlib.suppress(Exception):
                await self._raw_write(_build_led_frame(
                    _FLASH_COLOR_RGB, self._led_brightness_pct,
                ))
            await asyncio.sleep(_FLASH_DURATION_S)
            with contextlib.suppress(Exception):
                await self._raw_write(_build_led_frame(
                    _IDLE_COLOR_RGB, self._led_brightness_pct,
                ))
        finally:
            self._flash_in_flight = False

    def state(self) -> TrainState:
        # `_connected` is a coarse "connect() has been called" flag; not
        # useful for liveness. `_link_alive` is toggled by _raw_write's
        # success/failure and is the accurate view of whether the BuWizz
        # is currently reachable over BLE.
        return TrainState(
            train_id=self.train_id,
            direction=self._direction,
            power=self._power,
            connected=self._connected and self._link_alive,
        )

    # --- async internals ---------------------------------------------------

    async def _async_connect(self) -> None:
        from bleak import BleakClient, BleakScanner

        name = os.environ.get("CHOOCHOO_BUWIZZ_NAME", _DEFAULT_BLE_NAME)
        # Fast path: if we've seen the peer before, its BLE address survives
        # a power cycle, so skip the 10 s scan and connect straight to the
        # cached address. `BleakClient` accepts an address string or a
        # BLEDevice object interchangeably.
        if self._cached_address is not None:
            log.info(
                "[%s] reconnecting to cached BuWizz address %s",
                self.train_id, self._cached_address,
            )
            device_or_addr: object = self._cached_address
            address_for_log = self._cached_address
        else:
            log.info("[%s] scanning for BuWizz hub %r over BLE...", self.train_id, name)
            device = await BleakScanner.find_device_by_name(name, timeout=_SCAN_TIMEOUT_S)
            if device is None:
                raise RuntimeError(
                    f"No BLE device named {name!r} found within {_SCAN_TIMEOUT_S:.0f}s. "
                    "Is the BuWizz powered on? Override the name via CHOOCHOO_BUWIZZ_NAME."
                )
            device_or_addr = device
            address_for_log = device.address

        client = BleakClient(device_or_addr, timeout=_CONNECT_TIMEOUT_S)
        await client.connect()
        log.info("[%s] connected to BuWizz at %s", self.train_id, address_for_log)

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
        self._cached_address = address_for_log

        # Arm the device watchdog and start our keepalive task that re-sends
        # the last motor frame inside the watchdog window. The watchdog-arm
        # write also proves the link is live and flips _link_alive True.
        await self._raw_write(bytes([_CMD_WATCHDOG, _WATCHDOG_TIMEOUT_S]))
        # Set the idle indicator color (dim blue). Failure here is non-
        # fatal — the LED is cosmetic.
        with contextlib.suppress(Exception):
            await self._raw_write(_build_led_frame(
                _IDLE_COLOR_RGB, self._led_brightness_pct,
            ))
        loop = asyncio.get_running_loop()
        self._keepalive_task = loop.create_task(self._keepalive_loop())
        if self._reconnect_task is None:
            self._reconnect_task = loop.create_task(self._reconnect_loop())

    async def _reconnect_loop(self) -> None:
        """Watches `_link_alive`. When it's False, tear down the dead
        BleakClient and re-run `_async_connect` with exponential backoff.
        Runs until the object is disconnected (task cancelled)."""
        delay = _RECONNECT_INITIAL_S
        try:
            while True:
                # Check often; sleep long between attempts.
                await asyncio.sleep(0.25)
                if self._link_alive:
                    delay = _RECONNECT_INITIAL_S
                    continue

                # Drop the dead client so we can construct a fresh one.
                if self._client is not None:
                    try:
                        await self._client.disconnect()
                    except Exception:
                        log.debug(
                            "[%s] disconnect of dead client raised",
                            self.train_id, exc_info=True,
                        )
                    self._client = None
                    self._char = None
                # Cancel keepalive too — it can't work without a client.
                if self._keepalive_task is not None:
                    self._keepalive_task.cancel()
                    with contextlib.suppress(asyncio.CancelledError):
                        await self._keepalive_task
                    self._keepalive_task = None

                log.info(
                    "[%s] BLE link dead; reconnect attempt in %.1fs",
                    self.train_id, delay,
                )
                await asyncio.sleep(delay)
                try:
                    await self._async_connect()
                except Exception:
                    log.warning(
                        "[%s] reconnect attempt failed", self.train_id, exc_info=True,
                    )
                    delay = min(delay * 2, _RECONNECT_MAX_S)
                    # If the cached address is stale (e.g. the hub was
                    # renamed in the vendor app between sessions), fall
                    # back to a fresh scan on the next attempt.
                    self._cached_address = None
                else:
                    delay = _RECONNECT_INITIAL_S
                    log.info("[%s] reconnected", self.train_id)
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
            self._link_alive = False
            raise RuntimeError("BuWizz not connected")
        # write-without-response per the API ("No response is generated").
        try:
            await self._client.write_gatt_char(self._char, frame, response=False)
        except Exception:
            # Any failure here means the peer is unreachable. Flip the
            # liveness flag so state() reports disconnected. Re-raise so
            # callers can react (e.g. the keepalive logs it).
            self._link_alive = False
            raise
        else:
            self._link_alive = True

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
