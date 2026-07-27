"""Freeze the Modbus point-map layout.

These constants are the contract with every Modbus master on the wire and
with every operator's HMI. Renumbering them silently would rot every
existing operator manual and Zeek query. If a test in here fails, that
means someone moved an address — make sure the move was deliberate and
documented before adjusting the assertion."""

from __future__ import annotations

from choochoo.modbus_map import (
    CO_COUNT,
    CO_ESTOP,
    CO_SWITCH_TO_CURVE,
    CO_SWITCH_TO_STRAIGHT,
    DI_CONNECTED,
    DI_COUNT,
    DI_DIRECTION,
    DI_SWITCH_ONLINE,
    DI_SWITCH_POSITION_CURVE,
    DI_SWITCH_POSITION_STRAIGHT,
    HR_CMD_COUNTER,
    HR_COUNT,
    HR_LIGHT,
    HR_POWER,
    IR_COUNT,
    IR_CURRENT_POWER,
    IR_MAX_POWER,
    UNIT_ID,
)


def test_unit_id():
    assert UNIT_ID == 1


def test_holding_register_layout():
    assert (HR_POWER, HR_LIGHT, HR_CMD_COUNTER) == (0, 1, 2)
    assert HR_COUNT == 3


def test_input_register_layout():
    assert (IR_CURRENT_POWER, IR_MAX_POWER) == (0, 1)
    assert IR_COUNT == 2


def test_coil_layout():
    assert CO_ESTOP == 0
    assert CO_SWITCH_TO_STRAIGHT == 1
    assert CO_SWITCH_TO_CURVE == 2
    assert CO_COUNT == 3


def test_discrete_input_layout():
    assert DI_CONNECTED == 0
    assert DI_DIRECTION == 1
    assert DI_SWITCH_POSITION_STRAIGHT == 2
    assert DI_SWITCH_POSITION_CURVE == 3
    assert DI_SWITCH_ONLINE == 4
    assert DI_COUNT == 5
