"""Controller tests that exercise the message handler without a real broker."""

from __future__ import annotations

import json
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from choochoo.switch_controller import SwitchController, SwitchControllerConfig
from choochoo.switch_protocol import (
    SWITCH_COOLDOWN_S,
    ThrowOutcome,
    switch_cmd_topic,
    switch_event_topic,
)


class Clock:
    def __init__(self, t: float = 1000.0) -> None:
        self.t = t

    def __call__(self) -> float:
        return self.t

    def advance(self, dt: float) -> None:
        self.t += dt


@pytest.fixture
def controller() -> tuple[SwitchController, Clock]:
    c = SwitchController(SwitchControllerConfig(switch_id="sw1", switch_kind="fake"))
    c.client = MagicMock()
    clk = Clock()
    c.switch.set_clock(clk)
    c._clock = clk  # controller uses same clock for event timestamps
    c.switch.connect()
    return c, clk


def _msg(topic: str, payload: dict):
    return SimpleNamespace(topic=topic, payload=json.dumps(payload).encode())


def _published_events(client: MagicMock, switch_id: str) -> list[dict]:
    """Return only the payloads paho.publish() saw on the event topic."""
    topic = switch_event_topic(switch_id)
    out: list[dict] = []
    for call in client.publish.call_args_list:
        args, kwargs = call
        # paho publish signature: publish(topic, payload, qos=0, retain=False)
        t = args[0] if args else kwargs.get("topic")
        if t == topic:
            payload = args[1] if len(args) > 1 else kwargs.get("payload")
            out.append(json.loads(payload))
    return out


def test_throw_command_drives_switch(controller):
    c, _ = controller
    c._on_message(None, None, _msg(switch_cmd_topic("sw1", "throw"),
                                    {"action": "throw", "direction": "forward"}))
    assert c.switch.throws  # FakeSwitch recorded the throw
    events = _published_events(c.client, "sw1")
    assert events[-1]["outcome"] == ThrowOutcome.OK.value


def test_bad_direction_is_ignored(controller):
    c, _ = controller
    c._on_message(None, None, _msg(switch_cmd_topic("sw1", "throw"),
                                    {"action": "throw", "direction": "sideways"}))
    assert c.switch.throws == []
    assert _published_events(c.client, "sw1") == []


def test_non_json_payload_is_ignored(controller):
    c, _ = controller
    msg = SimpleNamespace(topic=switch_cmd_topic("sw1", "throw"), payload=b"not json")
    c._on_message(None, None, msg)
    assert c.switch.throws == []


def test_unknown_action_is_ignored(controller):
    c, _ = controller
    c._on_message(None, None, _msg(switch_cmd_topic("sw1", "selfdestruct"), {}))
    assert c.switch.throws == []


def test_cooldown_rejection_publishes_event(controller):
    c, clk = controller
    c._on_message(None, None, _msg(switch_cmd_topic("sw1", "throw"),
                                    {"action": "throw", "direction": "forward"}))
    clk.advance(SWITCH_COOLDOWN_S / 2)  # still inside cooldown
    c._on_message(None, None, _msg(switch_cmd_topic("sw1", "throw"),
                                    {"action": "throw", "direction": "reverse"}))
    assert len(c.switch.throws) == 1
    events = _published_events(c.client, "sw1")
    outcomes = [e["outcome"] for e in events]
    assert outcomes == [ThrowOutcome.OK.value, ThrowOutcome.COOLDOWN_REJECTED.value]


def test_shutdown_disconnects_switch_and_client():
    c = SwitchController(SwitchControllerConfig(switch_id="sw1", switch_kind="fake"))
    c.client = MagicMock()
    c.switch.connect()
    c._shutdown()
    assert c.switch.state().connected is False
    c.client.disconnect.assert_called_once()
