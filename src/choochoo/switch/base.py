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
        # Live BLE-link view, set by real backends when a write succeeds
        # (True) or fails (False). FakeSwitch doesn't touch it, so it
        # tracks `_connected` there.
        self._link_alive = False
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
        # Report the live BLE-link view: `_connected` is a coarse "has
        # connect() ever succeeded" flag; `_link_alive` is toggled by
        # real writes to reflect the current peer reachability. Both
        # must be True for consumers to treat the link as usable.
        return SwitchState(
            switch_id=self.switch_id,
            position=self._position,
            connected=self._connected and self._link_alive,
            last_throw_ts=self._last_throw_ts,
            cooldown_until_ts=self._cooldown_until_ts,
        )
