from __future__ import annotations

from abc import ABC, abstractmethod

from choochoo.protocol import Direction, TrainState


class TrainClient(ABC):
    """Abstract interface a controller talks to.

    Implementations: FakeTrain (dev), PoweredUpTrain (real BLE on the Pi).
    """

    def __init__(self, train_id: str) -> None:
        self.train_id = train_id

    @abstractmethod
    def connect(self) -> None: ...

    @abstractmethod
    def disconnect(self) -> None: ...

    @abstractmethod
    def motor(self, direction: Direction, power: int) -> None: ...

    @abstractmethod
    def stop(self) -> None: ...

    @abstractmethod
    def light(self, brightness: int) -> None: ...

    @abstractmethod
    def state(self) -> TrainState: ...
