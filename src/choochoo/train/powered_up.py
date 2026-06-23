"""Real Powered Up train via BLE.

Tested with the Lego Powered Up SmartHub (88009) and a TrainMotor on port A.
On macOS BLE goes through `bleak`, which needs the running terminal app to
hold Bluetooth permission (System Settings -> Privacy & Security -> Bluetooth).

`pylgbst` is imported lazily so the rest of the package stays importable
on hosts where BLE / pylgbst aren't available.
"""

from __future__ import annotations

import logging
import os
import time

from choochoo.protocol import Direction, TrainState
from choochoo.train.base import TrainClient

log = logging.getLogger(__name__)


def _patch_bleak_for_pylgbst() -> None:
    """pylgbst (1.3.0) was written against bleak 0.x and calls
    `bleak.discover(...)` and `bleak.connect(...)`, which were removed in
    bleak 2.x. Add shims so pylgbst's `cbleak` module keeps working
    without us forking it. Idempotent."""
    import bleak

    if not hasattr(bleak, "discover"):
        async def discover(timeout: float = 5.0, **kwargs):  # type: ignore[no-untyped-def]
            return await bleak.BleakScanner.discover(timeout=timeout, **kwargs)

        bleak.discover = discover  # type: ignore[attr-defined]

    if not hasattr(bleak, "connect"):
        # pylgbst's `bleak.connect(...)` only ever wraps BleakClient.connect,
        # but it's actually never called by the working code path — the real
        # call site is `bleak.discover` then `bleak.BleakClient(...)`. Keep a
        # stub so the symbol exists if pylgbst ever reaches for it.
        async def connect(*args, **kwargs):  # type: ignore[no-untyped-def]
            raise RuntimeError(
                "bleak.connect was removed in bleak 2.x; "
                "use bleak.BleakClient(device).connect() instead."
            )

        bleak.connect = connect  # type: ignore[attr-defined]

# How long to wait for a peripheral on port A to announce itself after
# the hub connects. The train motor usually attaches within a second or two.
_PORT_A_TIMEOUT_S = 10.0
_POLL_INTERVAL_S = 0.1


class PoweredUpTrain(TrainClient):
    def __init__(self, train_id: str) -> None:
        super().__init__(train_id)
        self._hub = None
        self._motor = None
        self._direction: Direction | None = None
        self._power = 0

    def connect(self) -> None:
        _patch_bleak_for_pylgbst()
        from pylgbst import get_connection_auto  # type: ignore[import-not-found]
        from pylgbst.hub import SmartHub  # type: ignore[import-not-found]

        # Lego lets users rename hubs in the Powered Up app. CHOOCHOO_HUB_NAME
        # overrides the BLE name pylgbst filters on; default is the factory
        # "Smart Hub" name.
        hub_name = os.environ.get("CHOOCHOO_HUB_NAME", SmartHub.DEFAULT_NAME)
        log.info("[%s] scanning for hub named %r over BLE...", self.train_id, hub_name)
        connection = get_connection_auto(hub_name=hub_name)
        self._hub = SmartHub(connection=connection)
        log.info("[%s] hub connected, waiting for motor on port A", self.train_id)

        deadline = time.monotonic() + _PORT_A_TIMEOUT_S
        while time.monotonic() < deadline:
            if self._hub.port_A is not None:
                self._motor = self._hub.port_A
                log.info(
                    "[%s] motor attached: %s",
                    self.train_id,
                    type(self._motor).__name__,
                )
                return
            time.sleep(_POLL_INTERVAL_S)

        raise RuntimeError(
            "No peripheral attached to port A within "
            f"{_PORT_A_TIMEOUT_S:.0f}s — is the train motor plugged in?"
        )

    def disconnect(self) -> None:
        if self._hub is not None:
            try:
                self.stop()
            finally:
                self._hub.disconnect()
                self._hub = None
                self._motor = None

    def motor(self, direction: Direction, power: int) -> None:
        if self._motor is None:
            raise RuntimeError("connect() first")
        # pylgbst.TrainMotor.power expects -1.0..1.0; sign encodes direction.
        signed = power / 100.0
        if direction is Direction.REVERSE:
            signed = -signed
        self._motor.power(param=signed)
        self._direction = direction
        self._power = power

    def stop(self) -> None:
        if self._motor is not None:
            self._motor.power(param=0)
        self._power = 0

    def light(self, brightness: int) -> None:
        # SmartHub LED is RGB, not a dimmable white. Map brightness to
        # an orange-on / off so the operator sees feedback when they
        # change the slider. brightness=0 turns it off.
        if self._hub is None or self._hub.led is None:
            return
        from pylgbst.peripherals import COLOR_NONE, COLOR_ORANGE  # type: ignore[import-not-found]

        self._hub.led.set_color(COLOR_NONE if brightness == 0 else COLOR_ORANGE)

    def state(self) -> TrainState:
        return TrainState(
            train_id=self.train_id,
            direction=self._direction,
            power=self._power,
            connected=self._hub is not None and self._motor is not None,
        )
