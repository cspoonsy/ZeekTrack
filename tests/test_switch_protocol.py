"""Wire-format tests for the switch protocol."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from choochoo.protocol import Direction
from choochoo.switch_protocol import (
    SWITCH_BURST_MS,
    SWITCH_COOLDOWN_S,
    SWITCH_MAX_BURST_MS,
    SWITCH_POWER,
    SwitchDiscovery,
    SwitchState,
    ThrowCommand,
    ThrowEvent,
    ThrowOutcome,
    switch_cmd_topic,
    switch_cmd_wildcard,
    switch_discovery_topic,
    switch_event_topic,
    switch_state_topic,
)


def test_topic_helpers():
    assert switch_cmd_topic("sw1", "throw") == "choochoo/switch/sw1/cmd/throw"
    assert switch_cmd_wildcard("sw1") == "choochoo/switch/sw1/cmd/+"
    assert switch_state_topic("sw1") == "choochoo/switch/sw1/state"
    assert switch_event_topic("sw1") == "choochoo/switch/sw1/event"
    assert switch_discovery_topic("sw1") == "choochoo/switch/sw1/discovery"


def test_throw_command_roundtrip():
    cmd = ThrowCommand(direction=Direction.FORWARD)
    payload = cmd.model_dump_json()
    parsed = ThrowCommand.model_validate_json(payload)
    assert parsed.action == "throw"
    assert parsed.direction is Direction.FORWARD


def test_throw_command_rejects_bad_direction():
    with pytest.raises(ValidationError):
        ThrowCommand.model_validate({"action": "throw", "direction": "sideways"})


def test_throw_event_carries_outcome():
    ev = ThrowEvent(
        switch_id="sw1",
        direction=Direction.REVERSE,
        outcome=ThrowOutcome.COOLDOWN_REJECTED,
        ts=1234.5,
    )
    parsed = ThrowEvent.model_validate_json(ev.model_dump_json())
    assert parsed.outcome is ThrowOutcome.COOLDOWN_REJECTED
    assert parsed.ts == 1234.5


def test_switch_state_defaults():
    s = SwitchState(switch_id="sw1")
    assert s.position == "unknown"
    assert s.connected is False
    assert s.last_throw_ts is None
    assert s.cooldown_until_ts is None


def test_switch_discovery_carries_max_burst():
    d = SwitchDiscovery(
        switch_id="sw1",
        cmd_topic="choochoo/switch/sw1/cmd/+",
        state_topic="choochoo/switch/sw1/state",
    )
    assert d.max_burst_ms == SWITCH_MAX_BURST_MS
    assert d.online is True


def test_safety_constants_invariants():
    assert 0 < SWITCH_BURST_MS <= SWITCH_MAX_BURST_MS
    assert 0 < SWITCH_POWER <= 255
    assert SWITCH_COOLDOWN_S > 0
