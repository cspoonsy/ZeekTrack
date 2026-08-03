"""Wire protocol for the BLE track switch.

The switch has its own topic tree, its own retained discovery beacon, and
its own hard-coded safety envelope. The envelope constants live here so
every consumer (client, controller, tests) refers to the same values.

Baseline security posture matches the train (see V1 in VULNERABILITIES.md):
anonymous MQTT, plaintext. Motor-burnout safety is a *client-side* concern,
not a security one — the constants below are what stops a spamming
publisher from cooking the motor.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, Field

from choochoo.protocol import Direction

SWITCH_TOPIC_ROOT = "choochoo/switch"

# --- Wire ↔ physical mapping ------------------------------------------------
# The switch mechanism's gear train determines the rack direction relative
# to motor rotation. sw1's current build maps wire `reverse` → Straight and
# wire `forward` → Curve (flipped from the earlier 3-gear layout). If you
# change the gear count again, flip these two constants and update
# `switch.js`, which keeps its own JS-side copy of the same mapping.
UI_STRAIGHT_WIRE_DIRECTION = Direction.REVERSE
UI_CURVE_WIRE_DIRECTION = Direction.FORWARD

# --- Safety envelope --------------------------------------------------------
# Hard-coded. Tuned against the real sw1 Circuit Cube with a 3-gear train
# driving a 4-stud rack — 60 didn't move it, 110 nudged it, 130 clears
# the load. Full travel initially measured at ~850 ms but the trailing
# time was stall against the end stop; tightened progressively as
# over-rotation showed up (500 → 300 → 100 → 200 ms as the sweet spot).
# Retune if the mechanism changes. If a throw ever fails to reach the
# stop, bump up in 50 ms steps.
SWITCH_BURST_MS = 250
SWITCH_POWER = 130
SWITCH_COOLDOWN_S = 2.0
# Hard ceiling. SwitchClient.throw() clamps any duration_ms argument to this
# value regardless of caller — defense in depth against a bug raising the
# nominal SWITCH_BURST_MS above what the mechanism tolerates.
SWITCH_MAX_BURST_MS = 1200


def switch_cmd_topic(switch_id: str, action: str) -> str:
    return f"{SWITCH_TOPIC_ROOT}/{switch_id}/cmd/{action}"


def switch_cmd_wildcard(switch_id: str) -> str:
    return f"{SWITCH_TOPIC_ROOT}/{switch_id}/cmd/+"


def switch_state_topic(switch_id: str) -> str:
    return f"{SWITCH_TOPIC_ROOT}/{switch_id}/state"


def switch_event_topic(switch_id: str) -> str:
    return f"{SWITCH_TOPIC_ROOT}/{switch_id}/event"


def switch_discovery_topic(switch_id: str) -> str:
    return f"{SWITCH_TOPIC_ROOT}/{switch_id}/discovery"


class ThrowOutcome(StrEnum):
    OK = "ok"
    COOLDOWN_REJECTED = "cooldown_rejected"
    BLE_ERROR = "ble_error"


class ThrowCommand(BaseModel):
    action: Literal["throw"] = "throw"
    direction: Direction


class ThrowEvent(BaseModel):
    switch_id: str
    direction: Direction
    outcome: ThrowOutcome
    ts: float


SwitchPosition = Literal["forward", "reverse", "unknown"]


class SwitchState(BaseModel):
    switch_id: str
    position: SwitchPosition = "unknown"
    connected: bool = False
    last_throw_ts: float | None = None
    cooldown_until_ts: float | None = None


class SwitchDiscovery(BaseModel):
    switch_id: str
    name: str = "Circuit Cubes Track Switch"
    firmware: str = "choochoo 0.1.0"
    capabilities: list[str] = Field(default_factory=lambda: ["throw"])
    cmd_topic: str
    state_topic: str
    max_burst_ms: int = SWITCH_MAX_BURST_MS
    cooldown_s: float = SWITCH_COOLDOWN_S
    online: bool = True
