"""Controller tests that exercise the message handler without a real broker."""

from __future__ import annotations

import json
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from choochoo.controller import Controller, ControllerConfig
from choochoo.protocol import MAX_POWER, Direction, cmd_topic


@pytest.fixture
def controller() -> Controller:
    c = Controller(ControllerConfig(train_id="t1", train_kind="fake"))
    c.client = MagicMock()
    return c


def _msg(topic: str, payload: dict):
    return SimpleNamespace(topic=topic, payload=json.dumps(payload).encode())


def test_motor_command_drives_train(controller: Controller):
    msg = _msg(cmd_topic("t1", "motor"), {"direction": "forward", "power": 40})
    controller._on_message(None, None, msg)
    state = controller.train.state()
    assert state.direction is Direction.FORWARD
    assert state.power == 40


def test_stop_command_zeroes_power(controller: Controller):
    go = _msg(cmd_topic("t1", "motor"), {"direction": "forward", "power": 50})
    controller._on_message(None, None, go)
    controller._on_message(None, None, _msg(cmd_topic("t1", "stop"), {}))
    assert controller.train.state().power == 0


def test_bad_payload_is_ignored(controller: Controller):
    msg = _msg(cmd_topic("t1", "motor"), {"direction": "sideways", "power": 50})
    controller._on_message(None, None, msg)
    assert controller.train.state().power == 0


def test_non_json_payload_is_ignored(controller: Controller):
    msg = SimpleNamespace(topic=cmd_topic("t1", "motor"), payload=b"not json")
    controller._on_message(None, None, msg)
    assert controller.train.state().power == 0


def test_unknown_action_is_ignored(controller: Controller):
    controller._on_message(None, None, _msg(cmd_topic("t1", "selfdestruct"), {}))
    assert controller.train.state().power == 0


def test_motor_power_is_clamped_to_max(controller: Controller):
    """Even if a publisher (or attacker) sends 100, the train sees MAX_POWER."""
    msg = _msg(cmd_topic("t1", "motor"), {"direction": "forward", "power": 100})
    controller._on_message(None, None, msg)
    assert controller.train.state().power == MAX_POWER


def test_motor_power_below_max_is_unchanged(controller: Controller):
    msg = _msg(cmd_topic("t1", "motor"), {"direction": "forward", "power": 30})
    controller._on_message(None, None, msg)
    assert controller.train.state().power == 30
