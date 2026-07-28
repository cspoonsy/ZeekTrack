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
# The switch mechanism has 3 gears between the motor and the rack, so motor
# rotation direction is inverted at the rack. Every planned switch in this
# range uses the same mechanism, so these constants are a fixed system
# invariant. `switch.js` keeps its own JS-side copy of the same mapping;
# both must stay in sync — Python is the authoritative source.
UI_STRAIGHT_WIRE_DIRECTION = Direction.FORWARD
UI_CURVE_WIRE_DIRECTION = Direction.REVERSE

# --- Safety envelope --------------------------------------------------------
# Hard-coded. Tuned against the real sw1 Circuit Cube with a 3-gear train
# driving a 4-stud rack — 60 didn't move it, 110 nudged it, 130 clears the
# load. Full travel measured at ~850 ms, tightened to 500 ms once we
# confirmed the rack reaches its end stop earlier than that (the rest was
# stall against the stop, which is what we want to avoid). Retune if the
# mechanism changes.
SWITCH_BURST_MS = 500
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
