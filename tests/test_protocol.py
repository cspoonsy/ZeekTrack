import pytest
from pydantic import ValidationError

from choochoo.protocol import (
    Direction,
    LightCommand,
    MotorCommand,
    cmd_topic,
    cmd_wildcard,
    state_topic,
)


def test_topic_builders():
    assert cmd_topic("t1", "motor") == "choochoo/train/t1/cmd/motor"
    assert cmd_wildcard("t1") == "choochoo/train/t1/cmd/+"
    assert state_topic("t1") == "choochoo/train/t1/state"


def test_motor_command_bounds():
    MotorCommand(direction=Direction.FORWARD, power=0)
    MotorCommand(direction=Direction.REVERSE, power=100)
    with pytest.raises(ValidationError):
        MotorCommand(direction=Direction.FORWARD, power=101)
    with pytest.raises(ValidationError):
        MotorCommand(direction=Direction.FORWARD, power=-1)


def test_light_command_bounds():
    LightCommand(brightness=0)
    LightCommand(brightness=10)
    with pytest.raises(ValidationError):
        LightCommand(brightness=11)
