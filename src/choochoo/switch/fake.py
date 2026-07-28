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
        # FakeSwitch has no real BLE link; treat "connected" as the sole
        # liveness signal so state().connected mirrors the ABC's rule.
        self._link_alive = True

    def disconnect(self) -> None:
        log.info("[%s] disconnect", self.switch_id)
        self._connected = False
        self._link_alive = False

    def _run_burst(self, direction: Direction, duration_ms: int) -> None:
        log.info("[%s] throw %s for %d ms", self.switch_id, direction, duration_ms)
        self.throws.append((direction, duration_ms))
