"""Wire protocol shared by publishers and the controller.

Topics:
    choochoo/train/<train_id>/cmd/<action>   publishers -> controller
    choochoo/train/<train_id>/state          controller -> subscribers
    choochoo/train/<train_id>/event          controller -> subscribers

Payloads are JSON-encoded Pydantic models. Keep them small and flat — they're
meant to be readable on the wire (Zeek, mosquitto_sub, Wireshark).
"""

from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, Field

TOPIC_ROOT = "choochoo/train"

# Hardware-safety cap. The protocol accepts 0-100 (because an attacker can
# publish anything), but the controller clamps motor power to this value
# before driving the train. Centralized so every layer can refer to it.
MAX_POWER = 50


def cmd_topic(train_id: str, action: str) -> str:
    return f"{TOPIC_ROOT}/{train_id}/cmd/{action}"


def cmd_wildcard(train_id: str) -> str:
    return f"{TOPIC_ROOT}/{train_id}/cmd/+"


def state_topic(train_id: str) -> str:
    return f"{TOPIC_ROOT}/{train_id}/state"


def event_topic(train_id: str) -> str:
    return f"{TOPIC_ROOT}/{train_id}/event"


def discovery_topic(train_id: str) -> str:
    return f"{TOPIC_ROOT}/{train_id}/discovery"


class Direction(StrEnum):
    FORWARD = "forward"
    REVERSE = "reverse"


class MotorCommand(BaseModel):
    action: Literal["motor"] = "motor"
    direction: Direction
    # Power 0-100. 0 coasts; use StopCommand to brake.
    power: int = Field(ge=0, le=100)


class StopCommand(BaseModel):
    action: Literal["stop"] = "stop"


class LightCommand(BaseModel):
    action: Literal["light"] = "light"
    # 0 = off, 10 = max on Powered Up hubs.
    brightness: int = Field(ge=0, le=10)


class TrainState(BaseModel):
    train_id: str
    direction: Direction | None = None
    power: int = 0
    connected: bool = False


class DiscoveryAnnouncement(BaseModel):
    """Retained "I exist" message — published by the controller on connect.

    Mirrors the Home Assistant MQTT discovery pattern: a single retained
    payload tells anyone subscribed to the discovery topic everything they
    need to know to interact with the device (topic structure, capabilities,
    firmware version). Convenient for legitimate UIs; equally convenient for
    an attacker doing reconnaissance.
    """

    train_id: str
    name: str = "Lego Powered Up Train"
    firmware: str = "choochoo 0.1.0"
    capabilities: list[str] = Field(default_factory=lambda: ["motor", "stop", "light"])
    cmd_topic: str
    state_topic: str
    max_power: int = MAX_POWER
    online: bool = True
