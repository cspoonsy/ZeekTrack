from __future__ import annotations

import logging

from choochoo.protocol import Direction, TrainState
from choochoo.train.base import TrainClient

log = logging.getLogger(__name__)


class FakeTrain(TrainClient):
    """In-memory train. Logs every command so you can watch the controller
    round-trip MQTT -> action without BLE hardware."""

    def __init__(self, train_id: str) -> None:
        super().__init__(train_id)
        self._connected = False
        self._direction: Direction | None = None
        self._power = 0

    def connect(self) -> None:
        log.info("[%s] connect", self.train_id)
        self._connected = True

    def disconnect(self) -> None:
        log.info("[%s] disconnect", self.train_id)
        self._connected = False

    def motor(self, direction: Direction, power: int) -> None:
        log.info("[%s] motor %s %d", self.train_id, direction, power)
        self._direction = direction
        self._power = power

    def stop(self) -> None:
        log.info("[%s] stop", self.train_id)
        self._power = 0

    def light(self, brightness: int) -> None:
        log.info("[%s] light %d", self.train_id, brightness)

    def state(self) -> TrainState:
        return TrainState(
            train_id=self.train_id,
            direction=self._direction,
            power=self._power,
            connected=self._connected,
        )
