"""Tests for the Modbus controller's command translation.

Drives `_TrainBlock.setValues` directly — no actual TCP server needed.
Verifies that holding-register writes for power/light, and coil writes
for E-stop, all produce the right `TrainClient` calls and clamp to
MAX_POWER.
"""

from __future__ import annotations

import pytest

from choochoo.modbus_controller import ModbusController, ModbusControllerConfig
from choochoo.modbus_map import (
    CO_ESTOP,
    HR_LIGHT,
    HR_POWER,
    encode_signed_power,
)
from choochoo.protocol import MAX_POWER, Direction


@pytest.fixture
def ctrl() -> ModbusController:
    return ModbusController(ModbusControllerConfig(train_kind="fake"))


def test_holding_register_drives_motor_forward(ctrl: ModbusController):
    ctrl._holding.setValues(HR_POWER, [encode_signed_power(40)])
    state = ctrl.train.state()
    assert state.direction is Direction.FORWARD
    assert state.power == 40


def test_holding_register_drives_motor_reverse(ctrl: ModbusController):
    ctrl._holding.setValues(HR_POWER, [encode_signed_power(-30)])
    state = ctrl.train.state()
    assert state.direction is Direction.REVERSE
    assert state.power == 30


def test_motor_power_clamped_to_max(ctrl: ModbusController):
    """Even an attacker writing the max signed value sees MAX_POWER applied."""
    ctrl._holding.setValues(HR_POWER, [encode_signed_power(99)])
    assert ctrl.train.state().power == MAX_POWER


def test_zero_power_stops_train(ctrl: ModbusController):
    ctrl._holding.setValues(HR_POWER, [encode_signed_power(40)])
    ctrl._holding.setValues(HR_POWER, [encode_signed_power(0)])
    assert ctrl.train.state().power == 0


def test_estop_coil_stops_train(ctrl: ModbusController):
    ctrl._holding.setValues(HR_POWER, [encode_signed_power(40)])
    assert ctrl.train.state().power == 40
    ctrl._coils.setValues(CO_ESTOP, [True])
    assert ctrl.train.state().power == 0
    # Coil latches back to 0 after the trip.
    assert ctrl._coils.getValues(CO_ESTOP, 1) == [False]


def test_light_register_routes_through(ctrl: ModbusController):
    # FakeTrain just logs light; verify the call doesn't raise.
    ctrl._holding.setValues(HR_LIGHT, [7])
    # No state assertion — light has no observable effect on FakeTrain state.
